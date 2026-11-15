use std::ffi::c_void;
use std::hash::{BuildHasher, RandomState};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_BYTE_BLOB,
    FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT8, FWP_UINT16, FWP_UINT32,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_INTERFACE_INDEX, FWPM_CONDITION_IP_LOCAL_PORT,
    FWPM_CONDITION_IP_PROTOCOL, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, FWPM_FILTER0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SESSION0, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
    FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0,
};
use windows_sys::core::GUID;

use super::strict::{Cond, FilterSpec, Layer, StrictRoute, Verdict};

const RPC_C_AUTHN_DEFAULT: u32 = u32::MAX;
const IPPROTO_ICMPV6: u8 = 58;
const ALL_ROUTERS: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
const NAME: &str = "concord strict-route";

/// An open filtering engine in a dynamic session: the filters added through it are removed
/// when it closes, including when the process dies.
pub struct Wfp {
    engine: isize,
}

impl Drop for Wfp {
    fn drop(&mut self) {
        // SAFETY: `engine` came from a successful `FwpmEngineOpen0` and is closed once.
        unsafe { FwpmEngineClose0(self.engine as HANDLE) };
    }
}

struct AppId(*mut FWP_BYTE_BLOB);

impl Drop for AppId {
    fn drop(&mut self) {
        let mut raw = self.0.cast::<c_void>();
        // SAFETY: the blob was allocated by `FwpmGetAppIdFromFileName0`, which this releases.
        unsafe { FwpmFreeMemory0(&raw mut raw) };
    }
}

fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn random_guid() -> GUID {
    let state = RandomState::new();
    let high = u128::from(state.hash_one(1u8));
    let low = u128::from(state.hash_one(2u8));
    GUID::from_u128(high << 64 | low)
}

fn condition(key: GUID) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: key,
        matchType: FWP_MATCH_EQUAL,
        ..Default::default()
    }
}

fn uint8(key: GUID, value: u8) -> FWPM_FILTER_CONDITION0 {
    let mut cond = condition(key);
    cond.conditionValue.r#type = FWP_UINT8;
    cond.conditionValue.Anonymous.uint8 = value;
    cond
}

fn uint16(key: GUID, value: u16) -> FWPM_FILTER_CONDITION0 {
    let mut cond = condition(key);
    cond.conditionValue.r#type = FWP_UINT16;
    cond.conditionValue.Anonymous.uint16 = value;
    cond
}

fn uint32(key: GUID, value: u32) -> FWPM_FILTER_CONDITION0 {
    let mut cond = condition(key);
    cond.conditionValue.r#type = FWP_UINT32;
    cond.conditionValue.Anonymous.uint32 = value;
    cond
}

/// The conditions of one filter. `routers` and `app` are what the pointers inside them
/// refer to, so they must outlive the call that adds the filter.
fn conditions(
    spec: &FilterSpec,
    app: *mut FWP_BYTE_BLOB,
    routers: &mut FWP_BYTE_ARRAY16,
) -> Vec<FWPM_FILTER_CONDITION0> {
    let mut out = Vec::new();
    for cond in &spec.conds {
        match *cond {
            Cond::SelfProcess => {
                let mut cond = condition(FWPM_CONDITION_ALE_APP_ID);
                cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                cond.conditionValue.Anonymous.byteBlob = app;
                out.push(cond);
            }
            Cond::Interface(index) => out.push(uint32(FWPM_CONDITION_INTERFACE_INDEX, index)),
            Cond::RemotePort(port) => out.push(uint16(FWPM_CONDITION_IP_REMOTE_PORT, port)),
            Cond::Icmpv6 {
                kind,
                to_all_routers,
            } => {
                out.push(uint8(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_ICMPV6));
                out.push(uint16(FWPM_CONDITION_IP_LOCAL_PORT, kind));
                out.push(uint16(FWPM_CONDITION_IP_REMOTE_PORT, 0));
                if to_all_routers {
                    routers.byteArray16 = ALL_ROUTERS;
                    let mut cond = condition(FWPM_CONDITION_IP_REMOTE_ADDRESS);
                    cond.conditionValue.r#type = FWP_BYTE_ARRAY16_TYPE;
                    cond.conditionValue.Anonymous.byteArray16 = routers;
                    out.push(cond);
                }
            }
        }
    }
    out
}

fn add_filter(
    engine: HANDLE,
    sublayer: GUID,
    spec: &FilterSpec,
    app: *mut FWP_BYTE_BLOB,
) -> io::Result<()> {
    let mut routers = FWP_BYTE_ARRAY16::default();
    let mut conds = conditions(spec, app, &mut routers);
    let mut name = wide(spec.name);
    let mut filter = FWPM_FILTER0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        subLayerKey: sublayer,
        layerKey: match spec.layer {
            Layer::V4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            Layer::V6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        },
        flags: if spec.clear_action_right {
            FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT
        } else {
            0
        },
        ..Default::default()
    };
    filter.action.r#type = match spec.verdict {
        Verdict::Permit => FWP_ACTION_PERMIT,
        Verdict::Block => FWP_ACTION_BLOCK,
    };
    filter.weight.r#type = FWP_UINT8;
    filter.weight.Anonymous.uint8 = spec.weight;
    if !conds.is_empty() {
        filter.numFilterConditions = u32::try_from(conds.len()).unwrap_or(0);
        filter.filterCondition = conds.as_mut_ptr();
    }
    let mut id = 0u64;
    // SAFETY: the engine is open, and `filter` points at `name`, `conds`, `routers` and the
    // application id, all of which live until the call returns.
    check(unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut id) })
}

pub fn install(strict: &StrictRoute) -> io::Result<Wfp> {
    let session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let mut handle: HANDLE = null_mut();
    // SAFETY: `session` and `handle` are valid for the call; a null server name is this machine.
    check(unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_DEFAULT, null(), &session, &mut handle) })?;
    let wfp = Wfp {
        engine: handle as isize,
    };

    let sublayer = random_guid();
    let mut name = wide(NAME);
    let layer = FWPM_SUBLAYER0 {
        subLayerKey: sublayer,
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: null_mut(),
        },
        weight: u16::MAX,
        ..Default::default()
    };
    // SAFETY: the engine is open and `layer` points at `name` for the duration of the call.
    check(unsafe { FwpmSubLayerAdd0(handle, &layer, null_mut()) })?;

    let exe: Vec<u16> = std::env::current_exe()?
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut app: *mut FWP_BYTE_BLOB = null_mut();
    // SAFETY: `exe` is NUL-terminated and `app` receives a blob that `AppId` frees.
    check(unsafe { FwpmGetAppIdFromFileName0(exe.as_ptr(), &mut app) })?;
    let app = AppId(app);

    for spec in strict.filters() {
        add_filter(handle, sublayer, &spec, app.0)
            .map_err(|err| io::Error::new(err.kind(), format!("{}: {err}", spec.name)))?;
    }
    Ok(wfp)
}
