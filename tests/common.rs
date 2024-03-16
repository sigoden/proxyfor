#![allow(unused)]

use anyhow::{anyhow, Result};
use async_compression::tokio::bufread::GzipEncoder;
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use http::{
    header::{CONTENT_ENCODING, CONTENT_TYPE},
    Method, StatusCode,
};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    service::service_fn,
    Request, Response,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto,
};
use proxyfor::{
    cert::CertificateAuthority,
    server::{PrintMode, Server, ServerBuilder},
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tokio::{net::TcpListener, sync::oneshot};
use tokio_graceful::Shutdown;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::io::ReaderStream;

pub const HELLO_WORLD: &str = "Hello, World!";
pub const WORLD: &str = "world";

async fn test_server(req: Request<Incoming>) -> Result<Response<BoxBody<Bytes, anyhow::Error>>> {
    if hyper_tungstenite::is_upgrade_request(&req) {
        let (res, ws) = hyper_tungstenite::upgrade(req, None)?;

        tokio::spawn(async move {
            let mut ws = ws.await.unwrap();

            while let Some(msg) = ws.next().await {
                let msg = msg.unwrap();
                if msg.is_close() {
                    break;
                }
                ws.send(Message::Text(WORLD.to_owned())).await.unwrap();
            }
        });

        let (parts, body) = res.into_parts();
        let bytes = body.collect().await?.to_bytes();
        let body = Full::new(bytes).map_err(|err| anyhow!("{err}")).boxed();

        return Ok(Response::from_parts(parts, body));
    }

    match (req.method(), req.uri().path()) {
        (&Method::GET, "/hello") => Ok(Response::new(
            Full::new(Bytes::from(HELLO_WORLD))
                .map_err(|err| anyhow!("{err}"))
                .boxed(),
        )),
        (&Method::GET, "/hello/gzip") => {
            let stream_body = StreamBody::new(
                ReaderStream::new(GzipEncoder::new(HELLO_WORLD.as_bytes()))
                    .map_ok(Frame::data)
                    .map_err(|err| anyhow!("{err}")),
            );
            let res = Response::builder()
                .header(CONTENT_ENCODING, "gzip")
                .status(StatusCode::OK)
                .body(BoxBody::new(stream_body))?;
            Ok(res)
        }
        (&Method::POST, "/echo") => {
            let content_type = req.headers().get(CONTENT_TYPE).cloned();
            let bytes = req.collect().await?.to_bytes();
            let body = Full::new(bytes).map_err(|err| anyhow!("{err}")).boxed();
            let mut res = Response::new(body);
            if let Some(content_type) = content_type {
                res.headers_mut().insert(CONTENT_TYPE, content_type);
            }
            Ok(res)
        }
        _ => {
            let mut res = Response::default();
            *res.status_mut() = StatusCode::NOT_FOUND;
            Ok(res)
        }
    }
}

pub async fn start_http_server() -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = oneshot::channel();

    tokio::spawn(async move {
        let server = auto::Builder::new(TokioExecutor::new());
        let shutdown = Shutdown::new(async { rx.await.unwrap_or_default() });
        let guard = shutdown.guard_weak();

        loop {
            tokio::select! {
                res = listener.accept() => {
                    let Ok((tcp, _)) = res else {
                        continue;
                    };

                    let server = server.clone();

                    shutdown.spawn_task(async move {
                        let _ = server
                            .serve_connection_with_upgrades(TokioIo::new(tcp), service_fn(test_server))
                            .await;
                    });
                }
                _ = guard.cancelled() => {
                    break;
                }
            }
        }

        shutdown.shutdown().await;
    });

    Ok((addr, tx))
}

pub async fn start_proxy(web: bool) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let server = build_proxy_server(web)?;
    run_proxy_server(server).await
}

pub async fn run_proxy_server(server: Arc<Server>) -> Result<(SocketAddr, oneshot::Sender<()>)> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await?;
    let proxy_addr = listener.local_addr()?;
    let stop = server.run(listener).await?;
    Ok((proxy_addr, stop))
}

pub fn build_proxy_server(web: bool) -> Result<Arc<Server>> {
    let ca = build_ca()?;
    let server = ServerBuilder::new(ca)
        .print_mode(PrintMode::Nothing)
        .web(web)
        .build();
    Ok(server)
}

pub fn build_proxy_client(proxy: &str) -> Result<reqwest::Client> {
    let proxy = reqwest::Proxy::all(proxy)?;
    let ca_cert_file = resolve_fixture_path("proxyfor-ca-cert.cer");
    let ca_cert_data = std::fs::read_to_string(ca_cert_file)?;
    let ca_cert = reqwest::tls::Certificate::from_pem(ca_cert_data.as_bytes())?;

    let client = reqwest::Client::builder()
        .proxy(proxy)
        .add_root_certificate(ca_cert)
        .no_brotli()
        .no_deflate()
        .no_gzip()
        .build()?;

    Ok(client)
}

pub fn build_client() -> Result<reqwest::Client> {
    let ca_cert_file = resolve_fixture_path("proxyfor-ca-cert.cer");
    let ca_cert_data = std::fs::read_to_string(ca_cert_file)?;
    let ca_cert = reqwest::tls::Certificate::from_pem(ca_cert_data.as_bytes())?;

    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .no_brotli()
        .no_deflate()
        .no_gzip()
        .build()?;

    Ok(client)
}

pub fn build_ca() -> Result<CertificateAuthority> {
    let ca_cert_file = resolve_fixture_path("proxyfor-ca-cert.cer");
    let private_key_file = resolve_fixture_path("proxyfor-key.pem");
    let ca = proxyfor::cert::init_ca(&ca_cert_file, &private_key_file)?;
    Ok(ca)
}

pub async fn fetch_subscribe(url: &str, mut count: usize) -> Result<String> {
    let client = build_client()?;
    let res = client.get(url).send().await.unwrap();
    let mut chunks = BytesMut::new();
    let mut stream = res.bytes_stream();
    while let Some(chunk) = stream.next().await {
        chunks.extend_from_slice(&chunk?);
        count -= 1;
        if count == 0 {
            break;
        }
    }
    let output = std::str::from_utf8(&chunks).unwrap();
    Ok(output.to_string())
}

pub fn resolve_fixture_path(path: &str) -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.push("tests");
    dir.push("fixtures");
    dir.push(path);
    dir
}

pub fn mask_text(text: &str) -> String {
    let re = fancy_regex::Regex::new(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z)|(\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} GMT)").unwrap();
    let text = re.replace_all(text, "<DATETIME>");
    let re = fancy_regex::Regex::new(r#"localhost:\d+"#).unwrap();
    let text = re.replace_all(&text, "localhost:<PORT>");
    let re = fancy_regex::Regex::new(r#""time": \d+,"#).unwrap();
    let text = re.replace_all(&text, r#""time": <TIME>,"#);
    let re = fancy_regex::Regex::new(r#""time":\d+,"#).unwrap();
    let text = re.replace_all(&text, r#""time":<TIME>,"#);
    text.to_string()
}
