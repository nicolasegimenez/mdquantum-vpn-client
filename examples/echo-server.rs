//! Local-only development server. Creates an ephemeral certificate and prints its path.
use anyhow::Result;
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let path = std::env::temp_dir().join(format!("mdquantum-dev-{}.pem", std::process::id()));
    std::fs::write(&path, cert.cert.pem())?;
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )?;
    let listener = TcpListener::bind("127.0.0.1:8443").await?;
    println!(
        "Local development server: 127.0.0.1:8443\nCertificate: {}",
        path.display()
    );
    let acceptor = TlsAcceptor::from(Arc::new(config));
    loop {
        let (tcp, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        // Sequential and bounded: this is a local test fixture, not a VPN server.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut tls = acceptor.accept(tcp).await?;
            let mut buf = [0; 8192];
            loop {
                let n = tls.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                tls.write_all(&buf[..n]).await?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await;
    }
}
