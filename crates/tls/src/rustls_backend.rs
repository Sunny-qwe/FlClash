use std::io;
use std::sync::Arc;

use concord_common::BoxStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{EchConfig, EchMode, Resumption, UnbufferedClientConnection};
use rustls::unbuffered::{ConnectionState, EncodeError, InsufficientSizeError, UnbufferedStatus};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme, SupportedProtocolVersion};
use rustls_pki_types::{CertificateDer, EchConfigListBytes, ServerName, UnixTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::TlsError;
use crate::client_auth::ClientAuth;
use crate::policy::{CertPolicy, provider, rustls_error};
use crate::record::{Keys, RecordStream};
use crate::record_io::RecordIo;
use crate::trust::ConfigKey;

#[derive(Debug)]
struct PolicyVerifier {
    policy: Arc<CertPolicy>,
}

impl ServerCertVerifier for PolicyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.clone());
        chain.extend(intermediates.iter().cloned());
        self.policy
            .verify(&chain, server_name, self.policy.now())
            .map_err(rustls_error)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.policy.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.policy.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.policy.algorithms().supported_schemes()
    }
}

pub(crate) fn client_config(
    policy: Arc<CertPolicy>,
    alpn: Vec<Vec<u8>>,
    client_auth: Option<ClientAuth>,
    tls13_only: bool,
    ech: Option<&[u8]>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let versions: &[&'static SupportedProtocolVersion] = if tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    if client_auth.is_some() || ech.is_some() {
        return client_config_versions(policy, alpn, client_auth, versions, ech);
    }
    let key = ConfigKey {
        policy: policy.key(),
        alpn: alpn.clone(),
        tls13_only,
    };
    let keeper = policy.clone();
    keeper.trust().shared_config(key, || {
        client_config_versions(policy, alpn, None, versions, None)
    })
}

pub(crate) fn client_config_versions(
    policy: Arc<CertPolicy>,
    alpn: Vec<Vec<u8>>,
    client_auth: Option<ClientAuth>,
    versions: &[&'static SupportedProtocolVersion],
    ech: Option<&[u8]>,
) -> Result<Arc<ClientConfig>, TlsError> {
    let builder = ClientConfig::builder_with_provider(provider());
    let builder = match ech {
        Some(list) => {
            let config = EchConfig::new(
                EchConfigListBytes::from(list.to_vec()),
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
            )
            .map_err(|err| TlsError::Config(format!("ech config: {err}")))?;
            builder
                .with_ech(EchMode::Enable(config))
                .map_err(|err| TlsError::Config(format!("ech: {err}")))?
        }
        None => builder
            .with_protocol_versions(versions)
            .map_err(|err| TlsError::Config(format!("tls versions: {err}")))?,
    };
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PolicyVerifier { policy }));
    let mut config = match client_auth {
        Some(auth) => builder
            .with_client_auth_cert(auth.chain, auth.key)
            .map_err(|err| TlsError::Config(format!("client certificate: {err}")))?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = alpn;
    config.resumption = Resumption::disabled();
    config.enable_secret_extraction = true;
    Ok(Arc::new(config))
}

pub(crate) async fn connect(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    io: BoxStream,
    aligned: bool,
) -> io::Result<RecordStream> {
    let mut io = if aligned {
        RecordIo::new(io)
    } else {
        RecordIo::unaligned(io)
    };
    let handover = handshake(config, name, &mut io).await?;
    let keys = Keys::from_rustls(handover.secrets, handover.kernel)?;
    Ok(RecordStream::new(
        io,
        keys,
        handover.alpn,
        handover.leftover,
        handover.early,
    ))
}

const HANDSHAKE_READ: usize = 16 * 1024 + 2048 + 5;
pub(crate) type RustlsStream = tokio_rustls::client::TlsStream<RecordIo<BoxStream>>;

pub(crate) async fn connect_buffered(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    io: BoxStream,
) -> io::Result<RustlsStream> {
    tokio_rustls::TlsConnector::from(config.clone())
        .connect(name, RecordIo::unaligned(io))
        .await
}

/// rustls joins a handshake message split across records in the input buffer itself, and takes
/// none above `MAX_HANDSHAKE_SIZE`: room for one such message, its header and the next record.
const MAX_HANDSHAKE_BUFFER: usize = 0xffff + 4 + HANDSHAKE_READ;

fn tls_error(err: rustls::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Drives rustls's unbuffered client to the end of the handshake, then takes the traffic
/// secrets so each direction can run its own record layer.
struct Handover {
    secrets: rustls::ExtractedSecrets,
    kernel: rustls::kernel::KernelConnection<rustls::client::ClientConnectionData>,
    alpn: Option<Vec<u8>>,
    leftover: Vec<u8>,
    early: Vec<u8>,
}

async fn handshake(
    config: &Arc<ClientConfig>,
    name: ServerName<'static>,
    io: &mut RecordIo<BoxStream>,
) -> io::Result<Handover> {
    let mut conn = UnbufferedClientConnection::new(config.clone(), name).map_err(tls_error)?;
    let mut incoming = vec![0u8; HANDSHAKE_READ];
    let mut used = 0;
    let mut outgoing: Vec<u8> = Vec::new();
    let mut encoded = 0;
    let mut early = Vec::new();
    loop {
        let UnbufferedStatus { discard, state } =
            conn.process_tls_records(incoming.get_mut(..used).unwrap_or_default());
        let mut blocked = false;
        let mut done = false;
        match state.map_err(tls_error)? {
            ConnectionState::EncodeTlsData(mut data) => loop {
                match data.encode(outgoing.get_mut(encoded..).unwrap_or_default()) {
                    Ok(n) => {
                        encoded += n;
                        break;
                    }
                    Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                        outgoing.resize(encoded + required_size, 0);
                    }
                    Err(err) => return Err(io::Error::other(err.to_string())),
                }
            },
            ConnectionState::TransmitTlsData(data) => {
                io.write_all(outgoing.get(..encoded).unwrap_or_default())
                    .await?;
                io.flush().await?;
                encoded = 0;
                data.done();
            }
            ConnectionState::BlockedHandshake => blocked = true,
            ConnectionState::ReadTraffic(mut traffic) => {
                while let Some(record) = traffic.next_record() {
                    early.extend_from_slice(record.map_err(tls_error)?.payload);
                }
            }
            ConnectionState::WriteTraffic(_) => done = true,
            ConnectionState::PeerClosed | ConnectionState::Closed => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake eof",
                ));
            }
            _ => return Err(io::Error::other("tls: unexpected handshake state")),
        }
        incoming.copy_within(discard..used, 0);
        used -= discard;
        if done {
            break;
        }
        if blocked {
            if used == incoming.len() {
                if incoming.len() >= MAX_HANDSHAKE_BUFFER {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls: handshake message too long",
                    ));
                }
                incoming.resize((incoming.len() * 2).min(MAX_HANDSHAKE_BUFFER), 0);
            }
            let n = io
                .read(incoming.get_mut(used..).unwrap_or_default())
                .await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tls handshake eof",
                ));
            }
            used += n;
        }
    }
    if encoded > 0 {
        io.write_all(outgoing.get(..encoded).unwrap_or_default())
            .await?;
        io.flush().await?;
    }
    let alpn = conn.alpn_protocol().map(<[u8]>::to_vec);
    let (secrets, kernel) = conn.dangerous_into_kernel_connection().map_err(tls_error)?;
    incoming.truncate(used);
    Ok(Handover {
        secrets,
        kernel,
        alpn,
        leftover: incoming,
        early,
    })
}
