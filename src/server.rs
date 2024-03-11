use crate::{
    certificate_authority::CertificateAuthority,
    filter::{is_match_title, is_match_type, Filter},
    recorder::{ErrorRecorder, PrintMode, Recorder},
    rewind::Rewind,
    state::State,
};

use anyhow::{anyhow, Result};
use async_compression::tokio::write::{BrotliDecoder, DeflateDecoder, GzipDecoder};
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use http::{
    header::{
        CACHE_CONTROL, CONNECTION, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE,
        PROXY_AUTHORIZATION,
    },
    uri::{Authority, Scheme},
    HeaderValue,
};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::{
    body::{Frame, Incoming},
    header::{CONTENT_ENCODING, HOST},
    service::service_fn,
    Method, StatusCode, Uri,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use serde::Serialize;
use std::sync::{atomic::AtomicBool, Arc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::BroadcastStream;

const WEB_INDEX: &str = include_str!("../assets/index.html");
const CERT_INDEX: &str = include_str!("../assets/install-certificate.html");
const CERT_PREFIX: &str = "http://proxyfor.local/";
pub(crate) const WEB_PREFIX: &str = "/__proxyfor__";

type Request = hyper::Request<Incoming>;
type Response = hyper::Response<BoxBody<Bytes, anyhow::Error>>;

pub(crate) struct Server {
    pub(crate) reverse_proxy_url: Option<String>,
    pub(crate) ca: CertificateAuthority,
    pub(crate) filters: Vec<Filter>,
    pub(crate) mime_filters: Vec<String>,
    pub(crate) state: State,
    pub(crate) web: bool,
    #[allow(unused)]
    pub(crate) running: Arc<AtomicBool>,
}

impl Server {
    pub(crate) async fn handle(self: Arc<Self>, req: Request) -> Result<Response, hyper::Error> {
        let mut res = Response::default();

        let req_uri = req.uri().to_string();
        let req_headers = req.headers().clone();
        let method = req.method().clone();

        let url = if !req_uri.starts_with('/') || req_uri.starts_with(WEB_PREFIX) {
            req_uri.clone()
        } else if let Some(base_url) = &self.reverse_proxy_url {
            if req_uri == "/" {
                base_url.clone()
            } else {
                format!("{base_url}{req_uri}")
            }
        } else {
            let mut recorder = Recorder::new(&req_uri, method.as_str());
            if self.web {
                recorder.change_print_mode(PrintMode::Oneline);
            }
            self.internal_server_error(&mut res, "No reserver proxy url", recorder);
            return Ok(res);
        };

        let path = match url.split_once('?') {
            Some((v, _)) => v,
            None => url.as_str(),
        };

        if let Some(path) = path.strip_prefix(CERT_PREFIX) {
            if let Err(err) = self.handle_cert_index(&mut res, path).await {
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                set_res_body(&mut res, err.to_string());
            };
            return Ok(res);
        } else if let Some(path) = path.strip_prefix(WEB_PREFIX) {
            if !self.web {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                set_res_body(
                    &mut res,
                    "The web interface is disabled. To enable it, run the command with the `--web` flag.".to_string(),
                );
                return Ok(res);
            }
            if method != Method::GET {
                *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
                return Ok(res);
            }
            set_cors_header(&mut res);
            let ret = if path.is_empty() || path == "/" {
                self.handle_web_index(&mut res).await
            } else if path == "/subscribe" {
                self.handle_subscribe(&mut res).await
            } else if path == "/traffics" {
                self.handle_list_traffics(&mut res).await
            } else if let Some(id) = path.strip_prefix("/traffic/") {
                let query = req.uri().query().unwrap_or_default();
                self.handle_get_traffic(&mut res, id, query).await
            } else {
                *res.status_mut() = StatusCode::NOT_FOUND;
                return Ok(res);
            };
            if let Err(err) = ret {
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                set_res_body(&mut res, err.to_string());
            }
            return Ok(res);
        }

        let mut recorder = Recorder::new(&req_uri, method.as_str());
        if self.web {
            recorder.change_print_mode(PrintMode::Oneline);
        }

        let req_version = req.version();
        recorder.set_req_version(&req_version);

        recorder.check_match(is_match_title(&self.filters, &format!("{method} {url}")));

        if method == Method::CONNECT {
            recorder.check_match(!self.filters.is_empty() || !self.mime_filters.is_empty());
            return self.handle_connect(req, recorder);
        }

        recorder.set_req_headers(&req_headers);

        let req_body = match req.collect().await {
            Ok(v) => v.to_bytes(),
            Err(err) => {
                self.internal_server_error(&mut res, err, recorder);
                return Ok(res);
            }
        };

        recorder.set_req_body(&req_body);

        let mut builder = hyper::Request::builder()
            .uri(&url)
            .method(method.clone())
            .version(req_version);
        for (key, value) in req_headers.iter() {
            if matches!(key, &HOST | &CONNECTION | &PROXY_AUTHORIZATION) {
                continue;
            }
            builder = builder.header(key.clone(), value.clone());
        }

        let proxy_req = match builder.body(Full::new(req_body)) {
            Ok(v) => v,
            Err(err) => {
                self.internal_server_error(&mut res, err, recorder);
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
                        .enable_all_versions()
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
                self.internal_server_error(&mut res, err, recorder);
                return Ok(res);
            }
        };

        let proxy_res_status = proxy_res.status();
        let proxy_res_headers = proxy_res.headers().clone();

        if let Some(header_value) = proxy_res_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
        {
            recorder.check_match(is_match_type(&self.mime_filters, header_value));
        }

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

        recorder
            .set_res_status(proxy_res_status)
            .set_res_version(&proxy_res.version())
            .set_res_headers(&proxy_res_headers);

        let proxy_res_body = match proxy_res.collect().await {
            Ok(v) => v.to_bytes(),
            Err(err) => {
                self.internal_server_error(&mut res, err, recorder);
                return Ok(res);
            }
        };

        if !proxy_res_body.is_empty() && recorder.is_valid() {
            let decompress_body = decompress(&proxy_res_body, encoding)
                .await
                .unwrap_or_else(|| proxy_res_body.to_vec());
            recorder.set_res_body(&decompress_body);
        }

        self.take_recorder(recorder);

        *res.body_mut() = Full::new(proxy_res_body)
            .map_err(|err| anyhow!("{err}"))
            .boxed();

        Ok(res)
    }

    async fn handle_cert_index(&self, res: &mut Response, path: &str) -> Result<()> {
        if path.is_empty() {
            set_res_body(res, CERT_INDEX.to_string());
            res.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=UTF-8"),
            );
        } else if path == "proxyfor-ca-cert.cer" || path == "proxyfor-ca-cert.pem" {
            let body = self.ca.ca_cert_pem();
            set_res_body(res, body);
            res.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/x-x509-ca-cert"),
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

    async fn handle_web_index(&self, res: &mut Response) -> Result<()> {
        set_res_body(res, WEB_INDEX.to_string());
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=UTF-8"),
        );
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        Ok(())
    }

    async fn handle_subscribe(&self, res: &mut Response) -> Result<()> {
        let (init_data, receiver) = (self.state.list(), self.state.subscribe());
        let stream = BroadcastStream::new(receiver);
        let stream = stream
            .map_ok(|head| ndjson_frame(&head))
            .map_err(|err| anyhow!("{err}"));
        let body = if init_data.is_empty() {
            BodyExt::boxed(StreamBody::new(stream))
        } else {
            let init_stream =
                stream::iter(init_data.into_iter().map(|head| Ok(ndjson_frame(&head))));
            let combined_stream = init_stream.chain(stream);
            BodyExt::boxed(StreamBody::new(combined_stream))
        };
        *res.body_mut() = body;
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-ndjson; charset=UTF-8"),
        );
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        Ok(())
    }

    async fn handle_list_traffics(&self, res: &mut Response) -> Result<()> {
        set_res_body(res, serde_json::to_string_pretty(&self.state.list())?);
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=UTF-8"),
        );
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        Ok(())
    }

    async fn handle_get_traffic(&self, res: &mut Response, id: &str, query: &str) -> Result<()> {
        match id.parse().ok().and_then(|id| self.state.get_traffic(id)) {
            Some(traffic) => {
                match query {
                    "markdown" | "curl" | "har" | "res-body" => {
                        let (data, mime) = traffic.export(query)?;
                        set_res_body(res, data);
                        res.headers_mut()
                            .insert(CONTENT_TYPE, HeaderValue::from_str(mime)?);
                    }
                    _ => {
                        set_res_body(res, serde_json::to_string_pretty(&traffic)?);
                        res.headers_mut().insert(
                            CONTENT_TYPE,
                            HeaderValue::from_static("application/json; charset=UTF-8"),
                        );
                    }
                }
                res.headers_mut()
                    .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            }
            None => {
                *res.status_mut() = StatusCode::NOT_FOUND;
            }
        }
        Ok(())
    }

    fn handle_connect(
        self: Arc<Self>,
        mut req: Request,
        recorder: Recorder,
    ) -> Result<Response, hyper::Error> {
        let mut res = Response::default();
        let authority = match req.uri().authority().cloned() {
            Some(authority) => authority,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(res);
            }
        };
        let fut = async move {
            let mut recorder = ErrorRecorder::new(recorder);
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let mut upgraded = TokioIo::new(upgraded);

                    let mut buffer = [0; 4];
                    let bytes_read = match upgraded.read_exact(&mut buffer).await {
                        Ok(bytes_read) => bytes_read,
                        Err(e) => {
                            recorder
                                .add_error(format!("Failed to read from upgraded connection: {e}"));
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
                            recorder.add_error(format!("Websocket connect error: {e}"));
                        }
                    } else if buffer[..2] == *b"\x16\x03" {
                        let server_config = match self.ca.gen_server_config(&authority).await {
                            Ok(server_config) => server_config,
                            Err(e) => {
                                recorder.add_error(format!("Failed to build server config: {e}"));
                                return;
                            }
                        };

                        let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                recorder
                                    .add_error(format!("Failed to establish TLS Connection: {e}"));
                                return;
                            }
                        };

                        if let Err(e) = self
                            .serve_connect_stream(stream, Scheme::HTTPS, authority)
                            .await
                        {
                            if !e.to_string().starts_with("error shutting down connection") {
                                recorder.add_error(format!("HTTPS connect error: {e}"));
                            }
                        }
                    } else {
                        recorder.add_error(format!(
                            "Unknown protocol, read '{:02X?}' from upgraded connection",
                            &buffer[..bytes_read]
                        ));

                        let mut server = match TcpStream::connect(authority.as_str()).await {
                            Ok(server) => server,
                            Err(e) => {
                                recorder
                                    .add_error(format! {"Failed to connect to {authority}: {e}"});
                                return;
                            }
                        };

                        if let Err(e) =
                            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                        {
                            recorder.add_error(format!(
                                "Failed to tunnel unknown protocol to {}: {}",
                                authority, e
                            ));
                        }
                    }
                }
                Err(e) => {
                    recorder.add_error(format!("Upgrade error: {e}"));
                }
            };
        };

        tokio::spawn(fut);
        Ok(Response::default())
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

    fn take_recorder(&self, recorder: Recorder) {
        if recorder.is_valid() {
            recorder.print();
            self.state.add_traffic(recorder.take_traffic())
        }
    }

    fn internal_server_error<T: std::fmt::Display>(
        &self,
        res: &mut Response,
        error: T,
        mut recorder: Recorder,
    ) {
        recorder.add_error(error.to_string());
        self.take_recorder(recorder);
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    }
}

fn set_res_body(res: &mut Response, body: String) {
    let body = Bytes::from(body);
    if let Ok(header_value) = HeaderValue::from_str(&body.len().to_string()) {
        res.headers_mut().insert(CONTENT_LENGTH, header_value);
    }
    *res.body_mut() = Full::new(body).map_err(|err| anyhow!("{err}")).boxed();
}

fn set_cors_header(res: &mut Response) {
    res.headers_mut().insert(
        hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        hyper::header::HeaderValue::from_static("*"),
    );
    res.headers_mut().insert(
        hyper::header::ACCESS_CONTROL_ALLOW_METHODS,
        hyper::header::HeaderValue::from_static("GET,POST,PUT,PATCH,DELETE"),
    );
    res.headers_mut().insert(
        hyper::header::ACCESS_CONTROL_ALLOW_HEADERS,
        hyper::header::HeaderValue::from_static("Content-Type,Authorization"),
    );
}

fn ndjson_frame<T: Serialize>(head: &T) -> Frame<Bytes> {
    let data = match serde_json::to_string(head) {
        Ok(data) => format!("{data}\n"),
        Err(_) => String::new(),
    };
    Frame::data(Bytes::from(data))
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
