use anyhow::{anyhow, Result};
use bytes::Bytes;
use clap::Parser;
use hyper::{body::Incoming, service::service_fn, StatusCode};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};

use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::{
    convert::Infallible,
    fmt::Display,
    net::{IpAddr, SocketAddr, TcpListener as StdTcpListener},
};
use tokio::{net::TcpListener, task::JoinHandle};

const MAX_BYTES: usize = 1048576; // 1 Mb

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let addr: IpAddr = cli
        .bind
        .parse()
        .map_err(|_| anyhow!("Invalid bind '{}'", cli.bind))?;
    let running = Arc::new(AtomicBool::new(true));
    let base_url = if !cli.url.starts_with("http://") && !cli.url.starts_with("https://") {
        format!("http://{}", cli.url)
    } else {
        cli.url.clone()
    };
    let handle = serve(addr, cli.port, base_url, running.clone())?;
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
    #[clap(short = 'b', long, default_value = "127.0.0.1")]
    pub bind: String,
    /// Specify port to listen on
    #[clap(short = 'p', long, default_value_t = 8088)]
    pub port: u16,
    /// Specify url to monitor
    pub url: String,
}

type Request = hyper::Request<Incoming>;
type Response = hyper::Response<BoxBody<Bytes, Infallible>>;

struct Server {
    base_url: String,
    #[allow(unused)]
    running: Arc<AtomicBool>,
}

impl Server {
    async fn call(self: Arc<Self>, req: Request) -> Result<Response, hyper::Error> {
        let mut res = Response::default();

        let base_url = &self.base_url;
        let req_path = req.uri().to_string();
        let req_headers = req.headers().clone();
        let method = req.method().clone();

        let url = if !req_path.starts_with("/") {
            req_path.clone()
        } else if req_path == "/" {
            base_url.clone()
        } else {
            format!("{base_url}{req_path}")
        };

        let req_body = req.collect().await?.to_bytes();
        let req_body_pretty = format_bytes(&req_body);

        println!("# {method} {url}");

        println!(
            r#"
REQUEST HEADERS
{req_headers:?}

REQUEST BODY
{req_body_pretty}"#
        );

        let mut builder = hyper::Request::builder().uri(&url).method(method);
        for (key, value) in req_headers.iter() {
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
        for (key, value) in proxy_res_headers.iter() {
            res.headers_mut().insert(key.clone(), value.clone());
        }

        let proxy_res_body = proxy_res.collect().await?.to_bytes();
        let proxy_res_body_pretty = format_bytes(&proxy_res_body);

        *res.body_mut() = Full::new(proxy_res_body).boxed();

        println!(
            r#"
RESPONSE STATUS: {proxy_res_status}

RESPONSE HEADERS
{proxy_res_headers:?}

RESPONSE BODY
{proxy_res_body_pretty}"#
        );
        Ok(res)
    }
}

fn serve(
    addr: IpAddr,
    port: u16,
    base_url: String,
    running: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    let server_handle = Arc::new(Server { base_url, running });
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

fn format_bytes(data: &Bytes) -> String {
    let data = &data[0..MAX_BYTES.min(data.len())];
    if let Ok(value) = std::str::from_utf8(data) {
        value.to_string()
    } else {
        hexplay::HexView::new(data).to_string()
    }
}
