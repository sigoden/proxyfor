use anyhow::{anyhow, Context, Result};
use http::uri::Authority;
use moka::future::Cache;
use rand::{thread_rng, Rng};
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, SanType};
use std::{io::Cursor, sync::Arc};
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

const TTL_SECS: i64 = 365 * 24 * 60 * 60;
const CACHE_TTL: u64 = TTL_SECS as u64 / 2;
const NOT_BEFORE_OFFSET: i64 = 60;
const KEY_DATA: &str = include_str!("../assets/proxyfor-key.pem");
const CA_CERT_DATA: &str = include_str!("../assets/proxyfor-ca-cert.cer");

pub fn load_ca() -> Result<CertificateAuthority> {
    let key_err = || "Failed to read private key";
    let key = KeyPair::from_pem(KEY_DATA).with_context(key_err)?;
    let key_clone = KeyPair::from_pem(KEY_DATA).with_context(key_err)?;

    let ca_err = || "Failed to read CA certificate";
    let ca_params =
        CertificateParams::from_ca_cert_pem(CA_CERT_DATA, key_clone).with_context(ca_err)?;
    let ca_cert = Certificate::from_params(ca_params).with_context(ca_err)?;

    let mut key_reader = Cursor::new(KEY_DATA);
    let key_der = rustls_pemfile::read_one(&mut key_reader)
        .ok()
        .flatten()
        .and_then(|key| match key {
            rustls_pemfile::Item::Pkcs1Key(key) => Some(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => Some(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => Some(PrivateKeyDer::Sec1(key)),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Invalid private key"))?;

    let ca = CertificateAuthority::new(key, key_der, ca_cert, 1_000);
    Ok(ca)
}

pub struct CertificateAuthority {
    private_key: KeyPair,
    private_key_der: PrivateKeyDer<'static>,
    ca_cert: Certificate,
    cache: Cache<Authority, Arc<ServerConfig>>,
}

impl CertificateAuthority {
    pub fn new(
        private_key: KeyPair,
        private_key_der: PrivateKeyDer<'static>,
        ca_cert: Certificate,
        cache_size: u64,
    ) -> Self {
        Self {
            private_key,
            private_key_der,
            ca_cert,
            cache: Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(std::time::Duration::from_secs(CACHE_TTL))
                .build(),
        }
    }

    pub fn ca_cert_pem(&self) -> String {
        CA_CERT_DATA.to_string()
    }

    pub async fn gen_server_config(&self, authority: &Authority) -> Result<Arc<ServerConfig>> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            return Ok(server_cfg);
        }

        let certs = vec![self.gen_cert(authority)?];

        let mut server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key_der.clone_key())?;

        server_cfg.alpn_protocols = vec![
            #[cfg(feature = "http2")]
            b"h2".to_vec(),
            b"http/1.1".to_vec(),
        ];

        let server_cfg = Arc::new(server_cfg);

        self.cache
            .insert(authority.clone(), Arc::clone(&server_cfg))
            .await;

        Ok(server_cfg)
    }

    fn gen_cert(&self, authority: &Authority) -> Result<CertificateDer<'static>> {
        let mut params = CertificateParams::default();
        params.serial_number = Some(thread_rng().gen::<u64>().into());

        let not_before = OffsetDateTime::now_utc() - Duration::seconds(NOT_BEFORE_OFFSET);
        params.not_before = not_before;
        params.not_after = not_before + Duration::seconds(TTL_SECS);
        params
            .distinguished_name
            .push(DnType::CommonName, authority.host());
        params
            .subject_alt_names
            .push(SanType::DnsName(authority.host().into()));

        params.alg = self
            .private_key
            .compatible_algs()
            .next()
            .ok_or_else(|| anyhow!("Failed to find compatible algorithm"))?;

        let private_key_clone = KeyPair::from_pem(&self.private_key.serialize_pem())?;
        params.key_pair = Some(private_key_clone);

        let cert = Certificate::from_params(params)?;
        let cert_data = cert.serialize_pem_with_signer(&self.ca_cert)?;

        let mut cert_reader = Cursor::new(cert_data.as_bytes());
        let cert = rustls_pemfile::certs(&mut cert_reader)
            .next()
            .and_then(|v| v.ok())
            .ok_or_else(|| anyhow!("Invalid generated certificate"))?;

        Ok(cert)
    }
}
