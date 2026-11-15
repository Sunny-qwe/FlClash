use std::ffi::{CStr, c_char, c_int, c_void};
use std::io;
use std::net::IpAddr;
use std::ptr::null;
use std::sync::atomic::{AtomicU64, Ordering};

use core_foundation::array::CFArray;
use core_foundation::base::{Boolean, CFAllocatorRef, CFRelease, CFType, CFTypeRef, TCFType};
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};

type DynamicStoreRef = *const c_void;

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCDynamicStoreCreate(
        allocator: CFAllocatorRef,
        name: CFStringRef,
        callout: *const c_void,
        context: *mut c_void,
    ) -> DynamicStoreRef;
    fn SCDynamicStoreAddTemporaryValue(
        store: DynamicStoreRef,
        key: CFStringRef,
        value: CFTypeRef,
    ) -> Boolean;
    fn SCError() -> c_int;
    fn SCErrorString(status: c_int) -> *const c_char;
}

static NEXT_KEY: AtomicU64 = AtomicU64::new(0);

/// configd drops the key when this session closes, including when the process dies.
pub struct Registration {
    store: DynamicStoreRef,
}

// SAFETY: the store is only released after creation, and CFRelease may run on any thread.
unsafe impl Send for Registration {}

impl Drop for Registration {
    fn drop(&mut self) {
        // SAFETY: `store` is the non-null reference SCDynamicStoreCreate returned, released once.
        unsafe { CFRelease(self.store) };
    }
}

pub fn register(ifname: &str, servers: &[IpAddr]) -> io::Result<Registration> {
    let label = CFString::new(&format!("concord {ifname}"));
    // SAFETY: null allocator, callout and context are the defaults; `label` outlives the call.
    let store = unsafe {
        SCDynamicStoreCreate(
            null(),
            label.as_concrete_TypeRef(),
            null(),
            std::ptr::null_mut(),
        )
    };
    if store.is_null() {
        return Err(last_error("SCDynamicStoreCreate"));
    }
    let registration = Registration { store };
    let key = CFString::new(&format!(
        "State:/Network/Service/concord-{}-{}/DNS",
        std::process::id(),
        NEXT_KEY.fetch_add(1, Ordering::Relaxed),
    ));
    let value = resolver(servers);
    // SAFETY: `store`, `key` and `value` are live CF objects; the store retains what it keeps.
    let added = unsafe {
        SCDynamicStoreAddTemporaryValue(
            registration.store,
            key.as_concrete_TypeRef(),
            value.as_CFTypeRef(),
        )
    };
    if added == 0 {
        return Err(last_error("SCDynamicStoreAddTemporaryValue"));
    }
    Ok(registration)
}

fn resolver(servers: &[IpAddr]) -> CFDictionary<CFString, CFType> {
    let addresses: Vec<CFString> = servers
        .iter()
        .map(|server| CFString::new(&server.to_string()))
        .collect();
    CFDictionary::from_CFType_pairs(&[
        (
            CFString::from_static_string("ServerAddresses"),
            CFArray::from_CFTypes(&addresses).as_CFType(),
        ),
        (
            CFString::from_static_string("SupplementalMatchDomains"),
            CFArray::from_CFTypes(&[CFString::from_static_string("")]).as_CFType(),
        ),
        (
            CFString::from_static_string("SupplementalMatchOrders"),
            CFArray::from_CFTypes(&[CFNumber::from(1)]).as_CFType(),
        ),
    ])
}

fn last_error(call: &str) -> io::Error {
    // SAFETY: SCErrorString returns a static NUL-terminated string for any status.
    let message = unsafe { CStr::from_ptr(SCErrorString(SCError())) };
    io::Error::other(format!("{call}: {}", message.to_string_lossy()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> CFType {
        let values: Vec<CFString> = values.iter().map(|value| CFString::new(value)).collect();
        CFArray::from_CFTypes(&values).as_CFType()
    }

    #[test]
    fn the_resolver_is_a_catch_all_ahead_of_the_primary_service() {
        let servers = [
            "198.18.0.2".parse().unwrap(),
            "fdfe:dcba:9876::2".parse().unwrap(),
        ];
        let dict = resolver(&servers);
        let get = |key: &'static str| {
            dict.find(CFString::from_static_string(key))
                .unwrap()
                .clone()
        };

        assert_eq!(
            get("ServerAddresses"),
            strings(&["198.18.0.2", "fdfe:dcba:9876::2"])
        );
        assert_eq!(get("SupplementalMatchDomains"), strings(&[""]));
        assert_eq!(
            get("SupplementalMatchOrders"),
            CFArray::from_CFTypes(&[CFNumber::from(1)]).as_CFType()
        );
    }
}
