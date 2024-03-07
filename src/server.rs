use crate::{
    certificate_authority::CertificateAuthority,
    filter::{is_match_title, is_match_type, Filter},
    recorder::Recorder,
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

const CERT_SITE_INDEX: &[u8] = include_bytes!("../assets/install-certificate.html");
const CERT_SITE_URL: &str = "http://proxyfor.local/";

type Request = hyper::Request<Incoming>;
type Response = hyper::Response<BoxBody<Bytes, Infallible>>;

pub(crate) struct Server {
    pub(crate) reverse_proxy_url: Option<String>,
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

        let path = req.uri().to_string();
        let req_headers = req.headers().clone();
        let method = req.method().clone();

        let url = if !path.starts_with('/') {
            path.clone()
        } else if let Some(base_url) = &self.reverse_proxy_url {
            if path == "/" {
                base_url.clone()
            } else {
                format!("{base_url}{path}")
            }
        } else {
            Recorder::new(path.clone(), method.clone())
                .set_error("No reserver proxy url".to_string())
                .print();
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

        let mut should_print = is_match_title(&self.filters, &format!("{method} {url}"));

        if method == Method::CONNECT {
            let recorder = if should_print && !self.no_filter {
                Some(Recorder::new(path.clone(), method.clone()))
            } else {
                None
            };
            return self.handle_connect(req, recorder);
        }

        let mut recorder = Recorder::new(path.clone(), method.clone());

        recorder = recorder.set_req_headers(req_headers.clone());

        let req_body = match req.collect().await {
            Ok(v) => v.to_bytes(),
            Err(err) => {
                internal_server_error(&mut res, err, should_print, recorder);
                return Ok(res);
            }
        };

        recorder = recorder.set_req_body(req_body.clone());

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
                internal_server_error(&mut res, err, should_print, recorder);
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
                internal_server_error(&mut res, err, should_print, recorder);
                return Ok(res);
            }
        };

        let proxy_res_status = proxy_res.status();
        let proxy_res_headers = proxy_res.headers().clone();

        if should_print {
            if let Some(header_value) = proxy_res_headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
            {
                should_print = is_match_type(&self.mime_filters, header_value)
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

        let proxy_res_body = match proxy_res.collect().await {
            Ok(v) => v.to_bytes(),
            Err(err) => {
                internal_server_error(&mut res, err, should_print, recorder);
                return Ok(res);
            }
        };

        if should_print {
            recorder = recorder
                .set_res_status(proxy_res_status)
                .set_res_headers(proxy_res_headers.clone());

            if !proxy_res_body.is_empty() {
                let decompress_body = decompress(&proxy_res_body, encoding)
                    .await
                    .unwrap_or_else(|| proxy_res_body.to_vec());
                recorder = recorder.set_res_body(Bytes::from(decompress_body));
            }
            recorder.print();
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
        mut recorder: Option<Recorder>,
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
                    let mut record_error = |err: String| {
                        if let Some(recorder) = recorder.take() {
                            recorder.set_error(err).print()
                        }
                    };
                    let mut upgraded = TokioIo::new(upgraded);

                    let mut buffer = [0; 4];
                    let bytes_read = match upgraded.read_exact(&mut buffer).await {
                        Ok(bytes_read) => bytes_read,
                        Err(e) => {
                            record_error(format!("Failed to read from upgraded connection: {e}"));
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
                            record_error(format!("Websocket connect error: {e}"));
                        }
                    } else if buffer[..2] == *b"\x16\x03" {
                        let server_config = match self.ca.gen_server_config(&authority).await {
                            Ok(server_config) => server_config,
                            Err(e) => {
                                record_error(format!("Failed to build server config: {e}"));
                                return;
                            }
                        };

                        let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                record_error(format!("Failed to establish TLS Connection: {e}"));
                                return;
                            }
                        };

                        if let Err(e) = self
                            .serve_connect_stream(stream, Scheme::HTTPS, authority)
                            .await
                        {
                            if !e.to_string().starts_with("error shutting down connection") {
                                record_error(format!("HTTPS connect error: {e}"));
                            }
                        }
                    } else {
                        record_error(format!(
                            "Unknown protocol, read '{:02X?}' from upgraded connection",
                            &buffer[..bytes_read]
                        ));

                        let mut server = match TcpStream::connect(authority.as_str()).await {
                            Ok(server) => server,
                            Err(e) => {
                                record_error(format! {"Failed to connect to {authority}: {e}"});
                                return;
                            }
                        };

                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                        {
                            record_error(format!(
                                "Failed to tunnel unknown protocol to {}: {}",
                                authority, e
                            ));
                        }
                    }
                }
                Err(e) => {
                    if let Some(recorder) = recorder.take() {
                        recorder.set_error(format!("Upgrade error: {e}")).print();
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
    should_print: bool,
    recorder: Recorder,
) {
    if should_print {
        recorder.set_error(err.to_string()).print();
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
