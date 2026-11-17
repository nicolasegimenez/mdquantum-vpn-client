//! Post-Quantum VPN Client
//!
//! Establishes a strictly hybrid TLS connection. IP tunneling is not yet implemented.
//!
//! Post-quantum security comes from TLS 1.3 itself: the default rustls backend
//! offers the hybrid key exchange X25519MLKEM768 (X25519 + ML-KEM-768) first.
//!
//! # Usage
//!
//! ```text
//! vpn-client --port 1080 --server-domain vpn.example.com
//! vpn-client --port 1080 --server-domain vpn.example.com --server-port 8443
//! vpn-client --port 1080 --server-domain vpn.example.com --server-cert server.pem
//! ```

mod transport;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Parser;
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use tracing::info;
use tracing_subscriber::EnvFilter;

/// Post-quantum TLS client (IP tunneling is not yet implemented)
#[derive(Parser, Debug)]
struct CliArgs {
    /// SOCKS5 proxy port to listen on for incoming connections.
    #[arg(short, long, default_value = "1080", value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,

    /// Path to a .pem file with the CA certificate(s) to trust for the server.
    ///
    /// If provided, only these certificates are trusted. If not provided,
    /// the built-in Mozilla root list is used (not the system's list).
    #[arg(long)]
    server_cert: Option<PathBuf>,

    /// Server domain name to connect to.
    ///
    /// This is used for TLS SNI (Server Name Indication) and hostname
    /// verification during the TLS handshake.
    #[arg(short = 'd', long, value_parser = |name: &str| ServerName::try_from(name.to_owned()))]
    server_domain: ServerName<'static>,

    /// Server port to connect to.
    ///
    /// Defaults to 443 (standard HTTPS port) for TLS-based connections.
    #[arg(long, default_value = "443", value_parser = clap::value_parser!(u16).range(1..))]
    server_port: u16,
}

/// Returns the certificate authorities the client trusts for the server.
fn load_roots(server_cert: Option<&Path>) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    match server_cert {
        // A given file replaces the public roots: adding to them would pin nothing.
        Some(path) => {
            info!("Loading custom server certificate: {:?}", path);
            let reading = || format!("reading {}", path.display());
            for cert in CertificateDer::pem_file_iter(path).with_context(reading)? {
                roots
                    .add(cert.with_context(reading)?)
                    .with_context(reading)?;
            }
            if roots.is_empty() {
                bail!("no certificate found in {}", path.display());
            }
        }
        None => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
    }
    Ok(roots)
}

#[tokio::main]
async fn main() -> Result<()> {
    // Log at info level unless RUST_LOG says otherwise.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = CliArgs::parse();

    info!("Initializing Post-Quantum VPN Client");
    info!(
        "Target server: {}:{}",
        args.server_domain.to_str(),
        args.server_port
    );
    info!("SOCKS5 proxy port: {}", args.port);

    let config = transport::client_config(load_roots(args.server_cert.as_deref())?)?;
    let stream = transport::connect(args.server_domain, args.server_port, config).await?;
    let session = stream.get_ref().1;
    info!(version = ?session.protocol_version(), group = ?session.negotiated_key_exchange_group().map(|g| g.name()), "Hybrid TLS connection established; IP tunneling is not yet implemented");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_quantum_key_exchange_is_offered_first() {
        let config = transport::client_config(RootCertStore::empty()).unwrap();
        assert_eq!(
            config.crypto_provider().kx_groups[0].name(),
            rustls::NamedGroup::X25519MLKEM768
        );
    }

    #[test]
    fn server_cert_replaces_the_public_roots() {
        let two_certs: String = ["a.test", "b.test"]
            .map(|name| {
                rcgen::generate_simple_self_signed([name.to_owned()])
                    .unwrap()
                    .cert
                    .pem()
            })
            .concat();
        let path = std::env::temp_dir().join(format!("vpn-client-test-{}.pem", std::process::id()));
        std::fs::write(&path, two_certs).unwrap();
        let roots = load_roots(Some(&path));
        std::fs::remove_file(&path).unwrap();

        assert_eq!(roots.unwrap().len(), 2);
        assert_eq!(
            load_roots(None).unwrap().len(),
            webpki_roots::TLS_SERVER_ROOTS.len()
        );
        // A file without any certificate is an error, not an empty trust list.
        assert!(load_roots(Some(Path::new("Cargo.toml"))).is_err());
    }
}
