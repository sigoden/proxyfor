use anyhow::{anyhow, Context, Result};
use http::uri::Authority;
use moka::future::Cache;
use rand::{thread_rng, Rng};
use rcgen::{Certificate, CertificateParams, DnType, KeyPair, SanType};
use std::{fs, io::Cursor, sync::Arc};
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

const TTL_SECS: i64 = 365 * 24 * 60 * 60;
const CACHE_TTL: u64 = TTL_SECS as u64 / 2;
const NOT_BEFORE_OFFSET: i64 = 60;

pub fn load_ca() -> Result<CertificateAuthority> {
    let mut config_dir = dirs::home_dir().ok_or_else(|| anyhow!("No home dir"))?;
    config_dir.push(".forproxy");
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir)
            .with_context(|| format!("Failed to create config dir '{}'", config_dir.display()))?;
    }

    let ca_file = config_dir.join("forproxy-ca-cert.pem");
    let key_file = config_dir.join("forproxy-key.pem");
    let (ca_data, key_data) = if !ca_file.exists() {
        let err = || "Failed to generate CA certificate";
        let mut params = CertificateParams::new(["localhost".to_string()]);
        params.distinguished_name.push(DnType::CommonName, "forproxy");
        let cert = Certificate::from_params(params).with_context(err)?;
        let ca_data = cert.serialize_pem().with_context(err)?;
        let key_data = cert.serialize_private_key_pem();
        fs::write(&ca_file, &ca_data).with_context(err)?;
        fs::write(&key_file, &key_data).with_context(err)?;
        (ca_data, key_data)
    } else {
        let ca_data =
            fs::read_to_string(&ca_file).with_context(|| "Failed to read CA certificate")?;
        let key_data =
            fs::read_to_string(&key_file).with_context(|| "Failed to read private key")?;
        (ca_data, key_data)
    };

    let mut ca_reader = Cursor::new(ca_data.as_bytes());
    let ca_cert = rustls_pemfile::certs(&mut ca_reader)
        .next()
        .and_then(|v| v.ok())
        .ok_or_else(|| anyhow!("Invalid CA certificate"))?;

    let mut key_reader = Cursor::new(key_data.as_bytes());
    let private_key = rustls_pemfile::read_one(&mut key_reader)
        .ok()
        .flatten()
        .and_then(|key| match key {
            rustls_pemfile::Item::Pkcs1Key(key) => Some(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => Some(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => Some(PrivateKeyDer::Sec1(key)),
            _ => None,
        })
        .ok_or_else(|| anyhow!("Invalid private key"))?;

    let ca = CertificateAuthority::new(private_key, ca_cert, 1_000);
    Ok(ca)
}

pub struct CertificateAuthority {
    private_key: PrivateKeyDer<'static>,
    ca_cert: CertificateDer<'static>,
    cache: Cache<Authority, Arc<ServerConfig>>,
}

impl CertificateAuthority {
    pub fn new(
        private_key: PrivateKeyDer<'static>,
        ca_cert: CertificateDer<'static>,
        cache_size: u64,
    ) -> Self {
        Self {
            private_key,
            ca_cert,
            cache: Cache::builder()
                .max_capacity(cache_size)
                .time_to_live(std::time::Duration::from_secs(CACHE_TTL))
                .build(),
        }
    }

    pub async fn gen_server_config(&self, authority: &Authority) -> Result<Arc<ServerConfig>> {
        if let Some(server_cfg) = self.cache.get(authority).await {
            return Ok(server_cfg);
        }

        let certs = vec![self.gen_cert(authority)?];

        let mut server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, self.private_key.clone_key())?;

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
        let mut params = rcgen::CertificateParams::default();
        params.serial_number = Some(thread_rng().gen::<u64>().into());

        let not_before = OffsetDateTime::now_utc() - Duration::seconds(NOT_BEFORE_OFFSET);
        params.not_before = not_before;
        params.not_after = not_before + Duration::seconds(TTL_SECS);
        params.distinguished_name.push(DnType::CommonName, authority.host());
        params
            .subject_alt_names
            .push(SanType::DnsName(authority.host().to_owned()));

        let key_pair = KeyPair::from_der(self.private_key.secret_der())
            .with_context(|| "Failed to parse private key")?;
        params.alg = key_pair
            .compatible_algs()
            .next()
            .ok_or_else(|| anyhow!("Failed to find compatible algorithm"))?;
        params.key_pair = Some(key_pair);

        let key_pair = KeyPair::from_der(self.private_key.secret_der())
            .with_context(|| "Failed to parse private key")?;

        let ca_cert_params = rcgen::CertificateParams::from_ca_cert_der(&self.ca_cert, key_pair)
            .with_context(|| "Failed to parse CA certificate")?;
        let ca_cert = rcgen::Certificate::from_params(ca_cert_params)
            .with_context(|| "Failed to generate CA certificate")?;

        let cert = rcgen::Certificate::from_params(params)
            .with_context(|| "Failed to generate certificate")?;
        let cert_data = cert
            .serialize_pem_with_signer(&ca_cert)
            .with_context(|| "Failed to serialize certificate")?;

        let mut cert_reader = Cursor::new(&cert_data);
        let cert = rustls_pemfile::certs(&mut cert_reader)
            .next()
            .and_then(|v| v.ok())
            .ok_or_else(|| anyhow!("Invalid certificate"))?;

        Ok(cert)
    }
}
