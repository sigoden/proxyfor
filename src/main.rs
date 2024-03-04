use anyhow::{anyhow, Result};
use async_compression::tokio::write::{BrotliDecoder, DeflateDecoder, GzipDecoder};
use bytes::Bytes;
use clap::Parser;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::{
    body::Incoming,
    header::{CONTENT_ENCODING, HOST},
    service::service_fn,
    StatusCode,
};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{
    convert::Infallible,
    fmt::Display,
    net::{IpAddr, SocketAddr, TcpListener as StdTcpListener},
};
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

const MAX_BYTES: usize = 1048576; // 1 Mb

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let addr: IpAddr = cli
        .bind
        .parse()
        .map_err(|_| anyhow!("Invalid bind '{}'", cli.bind))?;
    let running = Arc::new(AtomicBool::new(true));
    let target = cli.target.map(|url| {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            format!("http://{}", url)
        } else {
            url
        }
    });
    let handle = serve(addr, cli.port, target, running.clone())?;
    let running = Arc::new(AtomicBool::new(true));
    println!("Listening on {}:{}", cli.bind, cli.port);
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Specify bind address or unix socket
    #[clap(short = 'b', long, default_value = "0.0.0.0")]
    pub bind: String,
    /// Specify port to listen on
    #[clap(short = 'p', long, default_value_t = 8088)]
    pub port: u16,
    /// Proxy target
    #[clap(value_name = "URL")]
    pub target: Option<String>,
}

type Request = hyper::Request<Incoming>;
type Response = hyper::Response<BoxBody<Bytes, Infallible>>;

struct Server {
    target: Option<String>,
    #[allow(unused)]
    running: Arc<AtomicBool>,
}

impl Server {
    async fn call(self: Arc<Self>, req: Request) -> Result<Response, hyper::Error> {
        let mut res = Response::default();

        let req_path = req.uri().to_string();
        let req_headers = req.headers().clone();
        let method = req.method().clone();

        let url = if !req_path.starts_with('/') {
            req_path.clone()
        } else if let Some(base_url) = &self.target {
            if req_path == "/" {
                base_url.clone()
            } else {
                format!("{base_url}{req_path}")
            }
        } else {
            println!("# {method} {req_path}");

            internal_server_error(&mut res, anyhow!("No forward target"));
            return Ok(res);
        };

        println!("# {method} {url}");

        let req_body = req.collect().await?.to_bytes();
        let req_body_pretty = format_bytes(&req_body);

        println!(
            r#"
## REQUEST HEADERS
{req_headers:?}

## REQUEST BODY
{req_body_pretty}"#
        );

        let mut builder = hyper::Request::builder().uri(&url).method(method);
        for (key, value) in req_headers.iter() {
            if key == HOST {
                continue;
            }
            builder = builder.header(key.clone(), value.clone());
        }

        let proxy_req = match builder.body(Full::new(req_body)) {
            Ok(v) => v,
            Err(err) => {
                internal_server_error(&mut res, err);
                return Ok(res);
            }
        };

        let builder = Client::builder(TokioExecutor::new());
        let proxy_res = if url.starts_with("https://") {
            builder
                .build(HttpsConnector::new())
                .request(proxy_req)
                .await
        } else {
            builder.build(HttpConnector::new()).request(proxy_req).await
        };
        let proxy_res = match proxy_res {
            Ok(v) => v,
            Err(err) => {
                internal_server_error(&mut res, err);
                return Ok(res);
            }
        };

        let proxy_res_status = proxy_res.status();
        let proxy_res_headers = proxy_res.headers().clone();

        *res.status_mut() = proxy_res_status;
        let mut encoding = "";
        for (key, value) in proxy_res_headers.iter() {
            if key == CONTENT_ENCODING {
                if let Ok(value) = value.to_str() {
                    encoding = value;
                }
            }
            res.headers_mut().insert(key.clone(), value.clone());
        }

        let proxy_res_body = proxy_res.collect().await?.to_bytes();
        let decompress_body = decompress(&proxy_res_body, encoding)
            .await
            .unwrap_or_else(|| proxy_res_body.to_vec());
        let proxy_res_body_pretty = format_bytes(&decompress_body);

        *res.body_mut() = Full::new(proxy_res_body).boxed();

        println!(
            r#"
## RESPONSE STATUS: {proxy_res_status}

## RESPONSE HEADERS
{proxy_res_headers:?}

## RESPONSE BODY
{proxy_res_body_pretty}"#
        );
        Ok(res)
    }
}

fn serve(
    addr: IpAddr,
    port: u16,
    target: Option<String>,
    running: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    let server_handle = Arc::new(Server { target, running });
    let listener = create_listener(SocketAddr::new(addr, port))?;
    let handle = tokio::spawn(async move {
        loop {
            let accept = match listener.accept().await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let (cnx, _) = accept;
            let stream = TokioIo::new(cnx);
            tokio::spawn(handle_stream(server_handle.clone(), stream));
        }
    });
    Ok(handle)
}

async fn handle_stream<T>(handle: Arc<Server>, stream: TokioIo<T>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let hyper_service =
        service_fn(move |request: hyper::Request<Incoming>| handle.clone().call(request));

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

fn create_listener(addr: SocketAddr) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024 /* Default backlog */)?;
    let std_listener = StdTcpListener::from(socket);
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;
    Ok(listener)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to install CTRL+C signal handler")
}

fn internal_server_error<T: Display>(res: &mut Response, err: T) {
    println!("ERROR: {err}");
    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
}

async fn decompress(data: &Bytes, encoding: &str) -> Option<Vec<u8>> {
    match encoding {
        "deflate" => decompress_deflate(data).await.ok(),
        "gzip" => decompress_gzip(data).await.ok(),
        "br" => decompress_br(data).await.ok(),
        _ => None,
    }
}

macro_rules! decompress_fn {
    ($fn_name:ident, $decoder:ident) => {
        async fn $fn_name(in_data: &[u8]) -> Result<Vec<u8>> {
            let mut decoder = $decoder::new(Vec::new());
            decoder.write_all(in_data).await?;
            decoder.shutdown().await?;
            Ok(decoder.into_inner())
        }
    };
}

decompress_fn!(decompress_deflate, DeflateDecoder);
decompress_fn!(decompress_gzip, GzipDecoder);
decompress_fn!(decompress_br, BrotliDecoder);

fn format_bytes(data: &[u8]) -> String {
    let data = &data[0..MAX_BYTES.min(data.len())];
    if let Ok(value) = std::str::from_utf8(data) {
        value.to_string()
    } else {
        hexplay::HexView::new(data).to_string()
    }
}
