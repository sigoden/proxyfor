mod certificate_authority;
mod cli;
mod filter;
mod recorder;
mod rewind;
mod server;

use crate::{certificate_authority::load_ca, cli::Cli, filter::parse_filters, server::Server};

use anyhow::{anyhow, Result};
use clap::Parser;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::{net::TcpListener, task::JoinHandle};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let ca = load_ca()?;
    let (ip, port) =
        parse_addr(&cli.listen).ok_or_else(|| anyhow!("Invalid addr '{}'", cli.listen))?;
    let running = Arc::new(AtomicBool::new(true));
    let reverse_proxy_url = cli.reverse_proxy_url.map(|url| {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            format!("http://{}", url)
        } else {
            url
        }
    });
    let filters = parse_filters(&cli.filters)?;
    let mime_filters: Vec<String> = cli.mime_filters.iter().map(|v| v.to_lowercase()).collect();
    let no_filter = filters.is_empty() && mime_filters.is_empty();
    let server = Arc::new(Server {
        reverse_proxy_url,
        ca,
        no_filter,
        filters,
        mime_filters,
        running: running.clone(),
    });
    let handle = run(server, ip, port).await?;
    let running = Arc::new(AtomicBool::new(true));
    eprintln!("Listening on {}:{}", ip, port);
    tokio::select! {
        ret = handle => {
            if let Err(e) = ret {
                eprintln!("{}", e);
            }
            Ok(())
        },
        _ = shutdown_signal() => {
            running.store(false, Ordering::SeqCst);
            Ok(())
        },
    }
}

async fn run(server: Arc<Server>, ip: IpAddr, port: u16) -> Result<JoinHandle<()>> {
    let listener = TcpListener::bind(SocketAddr::new(ip, port)).await?;
    let handle = tokio::spawn(async move {
        loop {
            let accept = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let (cnx, _) = accept;
            let stream = TokioIo::new(cnx);
            tokio::spawn(handle_stream(server.clone(), stream));
        }
    });
    Ok(handle)
}

async fn handle_stream<T>(handle: Arc<Server>, stream: TokioIo<T>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let hyper_service =
        service_fn(move |request: hyper::Request<Incoming>| handle.clone().handle(request));

    let ret = Builder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(stream, hyper_service)
        .await;

    if let Err(err) = ret {
        match err.downcast_ref::<std::io::Error>() {
            Some(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {}
            _ => eprintln!("Serving connection {}", err),
        }
    }
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

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler")
}
