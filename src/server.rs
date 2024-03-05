use crate::{certificate_authority::CertificateAuthority, rewind::Rewind};

use anyhow::{anyhow, Result};
use async_compression::tokio::write::{BrotliDecoder, DeflateDecoder, GzipDecoder};
use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::Incoming,
    header::{CONTENT_ENCODING, HOST},
    service::service_fn,
    Method, StatusCode, Uri,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use std::sync::{atomic::AtomicBool, Arc};
use std::{convert::Infallible, fmt::Display};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;

const HEX_VIEW_SIZE: usize = 320;

type Request = hyper::Request<Incoming>;
type Response = hyper::Response<BoxBody<Bytes, Infallible>>;

pub(crate) struct Server {
    pub(crate) target: Option<String>,
    pub(crate) ca: CertificateAuthority,
    #[allow(unused)]
    pub(crate) running: Arc<AtomicBool>,
}

impl Server {
    pub(crate) async fn handle(self: Arc<Self>, req: Request) -> Result<Response, hyper::Error> {
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
            println!(
                r#"
#{method} {req_path}

REQUEST HEADERS
```
{req_headers:?}
```"#
            );

            internal_server_error(&mut res, anyhow!("No forward target"));
            return Ok(res);
        };

        println!(
            r#"
# {method} {url}

REQUEST HEADERS
```
{req_headers:?}
```"#
        );

        if method == Method::CONNECT {
            return self.handle_connect(req);
        }

        let req_body = req.collect().await?.to_bytes();
        if !req_body.is_empty() {
            let req_body_pretty = format_bytes(&req_body);
            println!(
                r#"
## REQUEST BODY
```
{req_body_pretty}
```"#
            );
        }

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
                .build(
                    HttpsConnectorBuilder::new()
                        .with_webpki_roots()
                        .https_only()
                        .enable_http1()
                        .build(),
                )
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
RESPONSE STATUS: {proxy_res_status}

RESPONSE HEADERS
```
{proxy_res_headers:?}
```

RESPONSE BODY
```
{proxy_res_body_pretty}
```"#
        );
        Ok(res)
    }

    fn handle_connect(self: Arc<Self>, mut req: Request) -> Result<Response, hyper::Error> {
        let fut = async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let mut upgraded = TokioIo::new(upgraded);

                    let mut buffer = [0; 4];
                    let bytes_read = match upgraded.read_exact(&mut buffer).await {
                        Ok(bytes_read) => bytes_read,
                        Err(e) => {
                            println!("Failed to read from upgraded connection: {e}");
                            return;
                        }
                    };

                    let mut upgraded = Rewind::new_buffered(
                        upgraded,
                        bytes::Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                    );

                    if buffer == *b"GET " {
                        if let Err(e) = self.serve_connect_stream(upgraded, Scheme::HTTP).await {
                            println!("Websocket connect error: {e}");
                        }
                    } else if buffer[..2] == *b"\x16\x03" {
                        let authority = req
                            .uri()
                            .authority()
                            .expect("Uri doesn't contain authority");

                        let server_config = match self.ca.gen_server_config(authority).await {
                            Ok(server_config) => server_config,
                            Err(e) => {
                                println!("Failed to build server config: {e}");
                                return;
                            }
                        };

                        let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                println!("Failed to establish TLS Connection: {e}");
                                return;
                            }
                        };

                        if let Err(e) = self.serve_connect_stream(stream, Scheme::HTTPS).await {
                            if !e.to_string().starts_with("error shutting down connection") {
                                println!("HTTPS connect error: {e}");
                            }
                        }
                    } else {
                        println!(
                            "Unknown protocol, read '{:02X?}' from upgraded connection",
                            &buffer[..bytes_read]
                        );

                        let authority = req
                            .uri()
                            .authority()
                            .expect("Uri doesn't contain authority")
                            .as_ref();

                        let mut server = match TcpStream::connect(authority).await {
                            Ok(server) => server,
                            Err(e) => {
                                println! {"Failed to connect to {authority}: {e}"};
                                return;
                            }
                        };

                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                        {
                            println!("Failed to tunnel unknown protocol to {}: {}", authority, e);
                        }
                    }
                }
                Err(e) => println!("Upgrade error {e}"),
            };
        };

        tokio::spawn(fut);
        Ok(Response::new(BoxBody::new(Empty::new())))
    }

    async fn serve_connect_stream<I>(
        self: Arc<Self>,
        io: I,
        scheme: Scheme,
    ) -> Result<(), hyper::Error>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = service_fn(|mut req| {
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                let authority = parts
                    .headers
                    .get(hyper::header::HOST)
                    .expect("Host is a required header")
                    .as_bytes();
                parts.uri = {
                    let mut parts = parts.uri.into_parts();
                    parts.scheme = Some(scheme.clone());
                    parts.authority =
                        Some(Authority::try_from(authority).expect("Failed to parse authority"));
                    Uri::from_parts(parts).expect("Failed to build URI")
                };

                req = Request::from_parts(parts, body);
            };

            self.clone().handle(req)
        });

        let io = TokioIo::new(io);
        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .with_upgrades()
            .await
    }
}

fn internal_server_error<T: Display>(res: &mut Response, err: T) {
    println!("{err}");
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
    if let Ok(value) = std::str::from_utf8(data) {
        value.to_string()
    } else if data.len() > HEX_VIEW_SIZE * 2 {
        format!(
            "{}\n......\n{}",
            hexplay::HexView::new(&data[0..HEX_VIEW_SIZE]),
            hexplay::HexView::new(&data[data.len() - HEX_VIEW_SIZE..])
        )
    } else {
        hexplay::HexView::new(data).to_string()
    }
}
