use proxyfor::{
    cert::{init_ca, CertificateAuthority},
    filter::parse_title_filters,
    server::{PrintMode, ServerBuilder, WEB_PREFIX},
};

use anyhow::{anyhow, Result};
use clap::Parser;
use std::{
    fs,
    net::{IpAddr, SocketAddr},
};
use tokio::net::TcpListener;

const CA_CERT_FILENAME: &str = "proxyfor-ca-cert.cer";
const PRIVATE_KEY_FILENAME: &str = "proxyfor-key.pem";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");
    let ca = setup_ca()?;
    let (ip, port) =
        parse_addr(&cli.listen).ok_or_else(|| anyhow!("Invalid addr '{}'", cli.listen))?;
    let reverse_proxy_url = cli.reverse_proxy_url.map(sanitize_reverse_proxy_url);
    let title_filters = parse_title_filters(&cli.filters)?;
    let mime_filters: Vec<String> = cli.mime_filters.iter().map(|v| v.to_lowercase()).collect();
    let listener = TcpListener::bind(SocketAddr::new(ip, port)).await?;
    let print_mode = if cli.web {
        PrintMode::Oneline
    } else {
        PrintMode::Markdown
    };
    let server = ServerBuilder::new(ca)
        .reverse_proxy_url(reverse_proxy_url)
        .title_filters(title_filters)
        .mime_filters(mime_filters)
        .web(cli.web)
        .print_mode(print_mode)
        .build();
    let stop_server = server.run(listener).await?;
    eprintln!("HTTP(S) proxy listening at {}:{}", ip, port);
    if cli.web {
        eprintln!(
            "Web interface accessible at http://{}:{}{}/",
            ip, port, WEB_PREFIX
        );
    }
    shutdown_signal().await;
    let _ = stop_server.send(());
    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Listening ip and port address
    #[clap(short = 'l', long, value_name = "ADDR", default_value = "0.0.0.0:8080")]
    listen: String,
    /// Only inspect http(s) traffic whose `{method} {uri}` matches the regex
    #[clap(short = 'f', long, value_name = "REGEX")]
    filters: Vec<String>,
    /// Only inspect http(s) traffic whose content-type matches the value
    #[clap(short = 'm', long, value_name = "VALUE")]
    mime_filters: Vec<String>,
    /// Enable web interface
    #[clap(short = 'w', long)]
    web: bool,
    /// Reverse proxy url
    #[clap(value_name = "URL")]
    reverse_proxy_url: Option<String>,
}

fn setup_ca() -> Result<CertificateAuthority> {
    let mut config_dir = dirs::home_dir().ok_or_else(|| anyhow!("No home dir"))?;
    config_dir.push(".proxyfor");
    if !config_dir.exists() {
        fs::create_dir_all(&config_dir).map_err(|err| {
            anyhow!(
                "Failed to create config dir '{}', {err}",
                config_dir.display()
            )
        })?;
    }
    let ca_cert_file = config_dir.join(CA_CERT_FILENAME);
    let private_key_file = config_dir.join(PRIVATE_KEY_FILENAME);
    let ca = init_ca(&ca_cert_file, &private_key_file)?;
    Ok(ca)
}

fn parse_addr(value: &str) -> Option<(IpAddr, u16)> {
    if let Ok(port) = value.parse() {
        Some(("0.0.0.0".parse().unwrap(), port))
    } else if let Ok(ip) = value.parse() {
        Some((ip, 8080))
    } else if let Some((ip, port)) = value.rsplit_once(':') {
        if let (Some(ip), Some(port)) = (ip.parse().ok(), port.parse().ok()) {
            Some((ip, port))
        } else {
            None
        }
    } else {
        None
    }
}

fn sanitize_reverse_proxy_url(url: String) -> String {
    let url = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("http://{}", url)
    } else {
        url
    };
    if let Some(url) = url.strip_suffix('/') {
        url.to_string()
    } else {
        url
    }
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler")
}
