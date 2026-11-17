use anyhow::{Context, Result};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::{TlsConnector, client::TlsStream};

pub fn provider() -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    provider
}

pub fn client_config(roots: RootCertStore) -> Result<ClientConfig> {
    Ok(ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub async fn connect(
    name: ServerName<'static>,
    port: u16,
    config: ClientConfig,
) -> Result<TlsStream<TcpStream>> {
    timeout(Duration::from_secs(10), async {
        let socket = TcpStream::connect((name.to_str().as_ref(), port))
            .await
            .context("connecting TCP")?;
        TlsConnector::from(Arc::new(config))
            .connect(name, socket)
            .await
            .context("performing hybrid TLS handshake")
    })
    .await
    .context("connection exceeded 10 second timeout")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    use tokio_rustls::TlsAcceptor;

    async fn scenario(classic: bool, trusted: bool, name: &str, tls12: bool) -> Result<()> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let mut roots = RootCertStore::empty();
        if trusted {
            roots.add(cert.cert.der().clone())?;
        }
        let mut p = provider();
        if classic {
            p.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519];
        }
        let config = ServerConfig::builder_with_provider(Arc::new(p))
            .with_protocol_versions(&[if tls12 {
                &rustls::version::TLS12
            } else {
                &rustls::version::TLS13
            }])?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            if let Ok(mut tls) = TlsAcceptor::from(Arc::new(config)).accept(tcp).await {
                let mut buf = [0; 4];
                if tls.read_exact(&mut buf).await.is_ok() {
                    let _ = tls.write_all(&buf).await;
                }
            }
        });
        let result = timeout(Duration::from_secs(3), async {
            let tcp = TcpStream::connect(addr).await?;
            let mut tls = TlsConnector::from(Arc::new(client_config(roots)?))
                .connect(ServerName::try_from(name.to_owned())?, tcp)
                .await?;
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                tls.get_ref()
                    .1
                    .negotiated_key_exchange_group()
                    .unwrap()
                    .name(),
                rustls::NamedGroup::X25519MLKEM768
            );
            tls.write_all(b"ping").await?;
            let mut buf = [0; 4];
            tls.read_exact(&mut buf).await?;
            assert_eq!(&buf, b"ping");
            Ok::<_, anyhow::Error>(())
        })
        .await;
        server.abort();
        result.expect("test timed out")
    }
    #[tokio::test]
    async fn hybrid_roundtrip() {
        scenario(false, true, "localhost", false).await.unwrap();
    }
    #[tokio::test]
    async fn rejects_classical_only() {
        assert!(scenario(true, true, "localhost", false).await.is_err());
    }
    #[tokio::test]
    async fn rejects_untrusted_certificate() {
        assert!(scenario(false, false, "localhost", false).await.is_err());
    }
    #[tokio::test]
    async fn rejects_wrong_hostname() {
        assert!(scenario(false, true, "wrong.test", false).await.is_err());
    }
    #[tokio::test]
    async fn rejects_tls12() {
        assert!(scenario(true, true, "localhost", true).await.is_err());
    }
}
