use anyhow::{anyhow, Context, Result};
use http::uri::Authority;
use moka::future::Cache;
use rand::{rngs::OsRng, thread_rng, Rng};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String,
    IsCa, KeyPair, KeyUsagePurpose, SanType,
};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use std::{fs, io::Cursor, sync::Arc};
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig,
};

const CA_CERT_FILENAME: &str = "forproxy-ca-cert.cer";
const KEY_FILENAME: &str = "forproxy-key.pem";
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

    let ca_file = config_dir.join(CA_CERT_FILENAME);
    let key_file = config_dir.join(KEY_FILENAME);
    let (key, ca_cert) = if !ca_file.exists() {
        let key = gen_private_key().with_context(|| "Failed to generate private key")?;
        let ca_cert = gen_ca_cert(&key).with_context(|| "Failed to generate CA certificate")?;
        fs::write(&ca_file, ca_cert.pem())
            .with_context(|| format!("Failed to save CA certificate to '{}'", ca_file.display()))?;
        fs::write(&key_file, key.serialize_pem())
            .with_context(|| format!("Failed to save private key to '{}'", key_file.display()))?;
        (key, ca_cert)
    } else {
        let key_err = || format!("Failed to read private key at '{}'", key_file.display());
        let key_data = fs::read_to_string(&key_file).with_context(key_err)?;
        let key = KeyPair::from_pem(&key_data).with_context(key_err)?;

        let ca_err = || format!("Failed to read CA certificate at '{}'", ca_file.display());
        let ca_data = fs::read_to_string(&ca_file).with_context(ca_err)?;
        let ca_params = CertificateParams::from_ca_cert_pem(&ca_data).with_context(ca_err)?;
        let ca_cert = Certificate::generate_self_signed(ca_params, &key).with_context(ca_err)?;
        (key, ca_cert)
    };

    let mut key_reader = Cursor::new(key.serialize_pem());
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
        let mut params = rcgen::CertificateParams::default();
        params.serial_number = Some(thread_rng().gen::<u64>().into());

        let not_before = OffsetDateTime::now_utc() - Duration::seconds(NOT_BEFORE_OFFSET);
        params.not_before = not_before;
        params.not_after = not_before + Duration::seconds(TTL_SECS);
        params
            .distinguished_name
            .push(DnType::CommonName, authority.host());
        params
            .subject_alt_names
            .push(SanType::DnsName(Ia5String::try_from(authority.host())?));

        let cert =
            Certificate::generate(params, &self.private_key, &self.ca_cert, &self.private_key)?;

        let cert_data = cert.pem();
        let mut cert_reader = Cursor::new(cert_data.as_bytes());
        let cert = rustls_pemfile::certs(&mut cert_reader)
            .next()
            .and_then(|v| v.ok())
            .ok_or_else(|| anyhow!("Invalid generated certificate"))?;

        Ok(cert)
    }
}

fn gen_private_key() -> Result<KeyPair> {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let private_key_der = private_key.to_pkcs8_der()?;
    let private_key = rcgen::KeyPair::try_from(private_key_der.as_bytes())?;
    Ok(private_key)
}

fn gen_ca_cert(key: &KeyPair) -> Result<Certificate> {
    let mut params = CertificateParams::default();
    let (yesterday, tomorrow) = validity_period();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "forproxy");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "forproxy");
    params.not_before = yesterday;
    params.not_after = tomorrow;
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let ca_cert = Certificate::generate_self_signed(params, key)?;
    Ok(ca_cert)
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let day = Duration::days(3650);
    let yesterday = OffsetDateTime::now_utc().checked_sub(day).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(day).unwrap();
    (yesterday, tomorrow)
}
