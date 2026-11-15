use std::error::Error;
use std::fmt::{self, Debug};
use std::io;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use concord_common::sync::lock;
use rustls::PeerIncompatible;
use rustls::internal::msgs::codec::Codec;

use crate::TlsError;

/// Where the `ECHConfigList` of a server comes from when the node does not carry one.
#[async_trait]
pub trait EchLookup: Send + Sync + Debug {
    async fn config_list(&self, server_name: &str) -> io::Result<Vec<u8>>;
}

/// BoringSSL's rejection of a handshake that sent ECH, with the `ECHConfigList` the server
/// answered with.
#[derive(Debug)]
pub(crate) struct BoringRejection {
    pub(crate) text: String,
    pub(crate) retry: Vec<u8>,
}

impl fmt::Display for BoringRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl Error for BoringRejection {}

/// The `ECHConfigList` a server answered a rejected ECH offer with, from either backend's error.
pub(crate) fn retry_list(err: &io::Error) -> Option<Vec<u8>> {
    let source = err.get_ref()?;
    if let Some(rejection) = source.downcast_ref::<BoringRejection>() {
        return Some(rejection.retry.clone());
    }
    match source.downcast_ref::<rustls::Error>()? {
        rustls::Error::PeerIncompatible(PeerIncompatible::ServerRejectedEncryptedClientHello(
            Some(configs),
        )) if !configs.is_empty() => Some(configs.get_encoding()),
        _ => None,
    }
}

/// The last thing built for a looked-up list; a handshake builds again only when the list changed.
pub(crate) struct ByList<T> {
    last: Mutex<Option<(Vec<u8>, Arc<T>)>>,
}

impl<T> ByList<T> {
    pub(crate) fn new() -> Self {
        ByList {
            last: Mutex::new(None),
        }
    }

    pub(crate) async fn get(
        &self,
        lookup: &dyn EchLookup,
        server_name: &str,
        build: impl FnOnce(&[u8]) -> Result<Arc<T>, TlsError>,
    ) -> io::Result<Arc<T>> {
        let list = lookup.config_list(server_name).await.map_err(|err| {
            io::Error::new(err.kind(), format!("resolve ECH config error: {err}"))
        })?;
        let cached = lock(&self.last).clone();
        if let Some((seen, built)) = cached
            && seen == list
        {
            return Ok(built);
        }
        let built = build(&list)?;
        {
            let mut last = lock(&self.last);
            *last = Some((list, built.clone()));
        }
        Ok(built)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct Fixed(Mutex<io::Result<Vec<u8>>>);

    #[async_trait]
    impl EchLookup for Fixed {
        async fn config_list(&self, _: &str) -> io::Result<Vec<u8>> {
            match &*lock(&self.0) {
                Ok(list) => Ok(list.clone()),
                Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
            }
        }
    }

    #[tokio::test]
    async fn a_build_is_reused_until_the_list_changes() {
        let lookup = Fixed(Mutex::new(Ok(vec![1])));
        let builds = AtomicUsize::new(0);
        let cache = ByList::<u8>::new();
        let get = || {
            cache.get(&lookup, "a.test", |list| {
                builds.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(list[0]))
            })
        };
        assert_eq!(*get().await.unwrap(), 1);
        assert_eq!(*get().await.unwrap(), 1);
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        *lock(&lookup.0) = Ok(vec![2]);
        assert_eq!(*get().await.unwrap(), 2);
        assert_eq!(builds.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failed_lookup_names_the_step() {
        let lookup = Fixed(Mutex::new(Err(io::Error::other(
            "no ECH config found in DNS records",
        ))));
        let err = ByList::<u8>::new()
            .get(&lookup, "a.test", |_| Ok(Arc::new(0)))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "resolve ECH config error: no ECH config found in DNS records"
        );
    }
}
