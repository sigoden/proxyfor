use crate::{
    certificate_authority::CertificateAuthority,
    filter::{is_match_title, is_match_type, Filter},
    rewind::Rewind,
};

use anyhow::Result;
use async_compression::tokio::write::{BrotliDecoder, DeflateDecoder, GzipDecoder};
use bytes::Bytes;
use http::{
    header::{CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE},
    uri::{Authority, Scheme},
    HeaderValue,
};
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
const CERT_SITE_INDEX: &[u8] = include_bytes!("../assets/install-certificate.html");
const CERT_SITE_URL: &str = "http://proxyfor.local/";

type Request = hyper::Request<Incoming>;
type Response = hyper::Response<BoxBody<Bytes, Infallible>>;

pub(crate) struct Server {
    pub(crate) forward_url: Option<String>,
    pub(crate) ca: CertificateAuthority,
    pub(crate) filters: Vec<Filter>,
    pub(crate) mime_filters: Vec<String>,
    pub(crate) no_filter: bool,
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
        } else if let Some(base_url) = &self.forward_url {
            if req_path == "/" {
                base_url.clone()
            } else {
                format!("{base_url}{req_path}")
            }
        } else {
            println!(
                r#"
# {method} {req_path}

No forward target"#
            );
            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            return Ok(res);
        };

        if let Some(path) = url.strip_prefix(CERT_SITE_URL) {
            return match self.handle_cert_site(&mut res, path).await {
                Ok(()) => Ok(res),
                Err(err) => {
                    let body = err.to_string();
                    let body = Bytes::from(body);
                    *res.body_mut() = Full::new(body).boxed();
                    *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    Ok(res)
                }
            };
        }

        let title = format!("{method} {url}");
        let mut is_inspect = is_match_title(&self.filters, &title);

        if method == Method::CONNECT {
            let title = if is_inspect && !self.no_filter {
                Some(title.clone())
            } else {
                None
            };
            return self.handle_connect(req, title);
        }

        let mut res = Response::default();

        let mut inspect_contents = vec![];

        inspect_contents.push(format!("\n# {title}"));

        inspect_contents.push(format!(
            r#"REQUEST HEADERS
```
{req_headers:?}
```"#
        ));

        let req_body = req.collect().await?.to_bytes();
        if !req_body.is_empty() {
            let req_body_pretty = format_bytes(&req_body);
            inspect_contents.push(format!(
                r#"REQUEST BODY
```
{req_body_pretty}
```"#
            ));
        }

        let mut builder = hyper::Request::builder().uri(&url).method(method.clone());
        for (key, value) in req_headers.iter() {
            if key == HOST {
                continue;
            }
            builder = builder.header(key.clone(), value.clone());
        }

        let proxy_req = match builder.body(Full::new(req_body)) {
            Ok(v) => v,
            Err(err) => {
                internal_server_error(&mut res, err, is_inspect, &mut inspect_contents);
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
                internal_server_error(&mut res, err, is_inspect, &mut inspect_contents);
                return Ok(res);
            }
        };

        let proxy_res_status = proxy_res.status();
        let proxy_res_headers = proxy_res.headers().clone();

        if is_inspect {
            if let Some(header_value) = proxy_res_headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
            {
                is_inspect = is_match_type(&self.mime_filters, header_value)
            }
        };

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

        if is_inspect {
            inspect_contents.push(format!(
                r#"RESPONSE STATUS: {proxy_res_status}

RESPONSE HEADERS
```
{proxy_res_headers:?}
```"#
            ));

            if !proxy_res_body.is_empty() {
                let decompress_body = decompress(&proxy_res_body, encoding)
                    .await
                    .unwrap_or_else(|| proxy_res_body.to_vec());
                let proxy_res_body_pretty = format_bytes(&decompress_body);
                inspect_contents.push(format!(
                    r#"RESPONSE BODY
```
{proxy_res_body_pretty}
```"#
                ));
            }
            println!("{}", inspect_contents.join("\n\n"))
        }

        *res.body_mut() = Full::new(proxy_res_body).boxed();

        Ok(res)
    }

    async fn handle_cert_site(self: Arc<Self>, res: &mut Response, path: &str) -> Result<()> {
        if path.is_empty() {
            let body = Bytes::from_static(CERT_SITE_INDEX);
            let body_size = body.len();
            *res.body_mut() = Full::new(body).boxed();
            res.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=UTF-8"),
            );
            res.headers_mut().insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&body_size.to_string())?,
            );
        } else if path == "proxyfor-ca-cert.cer" || path == "proxyfor-ca-cert.pem" {
            let body = self.ca.ca_cert_pem();
            let body = Bytes::from(body);
            let body_size = body.len();
            *res.body_mut() = Full::new(body).boxed();
            res.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-x509-ca-cert"),
            );
            res.headers_mut().insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&body_size.to_string())?,
            );
            res.headers_mut().insert(
                CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!(r#"attachment; filename="{path}""#))?,
            );
        } else {
            *res.status_mut() = StatusCode::NOT_FOUND;
        }
        Ok(())
    }

    fn handle_connect(
        self: Arc<Self>,
        mut req: Request,
        mut title: Option<String>,
    ) -> Result<Response, hyper::Error> {
        let mut res = Response::new(BoxBody::new(Empty::new()));
        let authority = match req.uri().authority().cloned() {
            Some(authority) => authority,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(res);
            }
        };
        let fut = async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let mut print_error = |err: String| {
                        if let Some(title) = title.take() {
                            println!(
                                r#"
# {title}

{err}"#
                            );
                        }
                    };
                    let mut upgraded = TokioIo::new(upgraded);

                    let mut buffer = [0; 4];
                    let bytes_read = match upgraded.read_exact(&mut buffer).await {
                        Ok(bytes_read) => bytes_read,
                        Err(e) => {
                            print_error(format!("Failed to read from upgraded connection: {e}"));
                            return;
                        }
                    };

                    let mut upgraded = Rewind::new_buffered(
                        upgraded,
                        bytes::Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                    );

                    if buffer == *b"GET " {
                        if let Err(e) = self
                            .serve_connect_stream(upgraded, Scheme::HTTP, authority)
                            .await
                        {
                            print_error(format!("Websocket connect error: {e}"));
                        }
                    } else if buffer[..2] == *b"\x16\x03" {
                        let server_config = match self.ca.gen_server_config(&authority).await {
                            Ok(server_config) => server_config,
                            Err(e) => {
                                print_error(format!("Failed to build server config: {e}"));
                                return;
                            }
                        };

                        let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                print_error(format!("Failed to establish TLS Connection: {e}"));
                                return;
                            }
                        };

                        if let Err(e) = self
                            .serve_connect_stream(stream, Scheme::HTTPS, authority)
                            .await
                        {
                            if !e.to_string().starts_with("error shutting down connection") {
                                print_error(format!("HTTPS connect error: {e}"));
                            }
                        }
                    } else {
                        print_error(format!(
                            "Unknown protocol, read '{:02X?}' from upgraded connection",
                            &buffer[..bytes_read]
                        ));

                        let mut server = match TcpStream::connect(authority.as_str()).await {
                            Ok(server) => server,
                            Err(e) => {
                                print_error(format! {"Failed to connect to {authority}: {e}"});
                                return;
                            }
                        };

                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                        {
                            print_error(format!(
                                "Failed to tunnel unknown protocol to {}: {}",
                                authority, e
                            ));
                        }
                    }
                }
                Err(e) => {
                    if let Some(title) = title.take() {
                        println!(
                            r#"
# {title}

Upgrade error: {e}"#
                        );
                    }
                }
            };
        };

        tokio::spawn(fut);
        Ok(Response::new(BoxBody::new(Empty::new())))
    }

    async fn serve_connect_stream<I>(
        self: Arc<Self>,
        stream: I,
        scheme: Scheme,
        authority: Authority,
    ) -> Result<(), Box<dyn std::error::Error + Sync + Send>>
    where
        I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let service = service_fn(|mut req| {
            if req.version() == hyper::Version::HTTP_10 || req.version() == hyper::Version::HTTP_11
            {
                let (mut parts, body) = req.into_parts();

                parts.uri = {
                    let mut parts = parts.uri.into_parts();
                    parts.scheme = Some(scheme.clone());
                    parts.authority = Some(authority.clone());
                    Uri::from_parts(parts).expect("Failed to build URI")
                };

                req = Request::from_parts(parts, body);
            };

            self.clone().handle(req)
        });

        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
            .await
    }
}

fn internal_server_error<T: Display>(
    res: &mut Response,
    err: T,
    is_inspect: bool,
    inspect_contents: &mut Vec<String>,
) {
    if is_inspect {
        inspect_contents.push(err.to_string());
        println!("{}", inspect_contents.join("\n\n"))
    }
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
