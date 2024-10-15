use crate::{
    cert::CertificateAuthority,
    filter::{is_match_title, is_match_type, TitleFilter},
    rewind::Rewind,
    state::State,
    traffic::{extract_mime, Traffic},
    utils::*,
};

use anyhow::{anyhow, Context as _, Result};
use bytes::Bytes;
use futures_util::{stream, Sink, SinkExt, Stream, StreamExt, TryStreamExt};
use http::{
    header::{
        CACHE_CONTROL, CONNECTION, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH,
        CONTENT_TYPE, PROXY_AUTHORIZATION,
    },
    uri::{Authority, Scheme},
    HeaderValue,
};
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::{
    body::{Body, Frame, Incoming},
    header::HOST,
    service::service_fn,
    upgrade::Upgraded,
    Method, StatusCode, Uri,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_tungstenite::WebSocketStream;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::{TokioExecutor, TokioIo},
};
use pin_project_lite::pin_project;
use serde::Serialize;
use std::{
    fs::File,
    io::Write,
    path::PathBuf,
    pin::Pin,
    process,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_graceful::Shutdown;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::BroadcastStream;
use tokio_tungstenite::tungstenite;

pub const CERT_PREFIX: &str = "http://proxyfor.local/";
pub const WEB_PREFIX: &str = "/__proxyfor__";
const WEB_INDEX: &str = include_str!("../assets/index.html");
const CERT_INDEX: &str = include_str!("../assets/install-certificate.html");

type Request = hyper::Request<Incoming>;
type Response = hyper::Response<BoxBody<Bytes, anyhow::Error>>;
type TrafficDoneSender = mpsc::UnboundedSender<(usize, u64)>;

pub struct ServerBuilder {
    ca: CertificateAuthority,
    reverse_proxy_url: Option<String>,
    title_filters: Vec<TitleFilter>,
    mime_filters: Vec<String>,
    web: bool,
    print_mode: PrintMode,
}

impl ServerBuilder {
    pub fn new(ca: CertificateAuthority) -> Self {
        Self {
            ca,
            reverse_proxy_url: None,
            title_filters: vec![],
            mime_filters: vec![],
            web: false,
            print_mode: PrintMode::Markdown,
        }
    }

    pub fn reverse_proxy_url(mut self, reverse_proxy_url: Option<String>) -> Self {
        self.reverse_proxy_url = reverse_proxy_url;
        self
    }

    pub fn title_filters(mut self, filters: Vec<TitleFilter>) -> Self {
        self.title_filters = filters;
        self
    }
    pub fn mime_filters(mut self, mime_filters: Vec<String>) -> Self {
        self.mime_filters = mime_filters;
        self
    }

    pub fn web(mut self, web: bool) -> Self {
        self.web = web;
        self
    }

    pub fn print_mode(mut self, print_mode: PrintMode) -> Self {
        self.print_mode = print_mode;
        self
    }

    pub fn build(self) -> Arc<Server> {
        let temp_dir = std::env::temp_dir().join(format!("proxyfor-{}", process::id()));
        info!(
            "reverse_proxy_url={:?}, title_filters={:?}, mime_filters={:?}, web={}, temp_dir={}",
            self.reverse_proxy_url,
            self.title_filters,
            self.mime_filters,
            self.web,
            temp_dir.display(),
        );
        Arc::new(Server {
            ca: self.ca,
            reverse_proxy_url: self.reverse_proxy_url,
            title_filters: self.title_filters,
            mime_filters: self.mime_filters,
            web: self.web,
            state: Arc::new(State::new(self.print_mode)),
            temp_dir,
        })
    }
}

pub struct Server {
    ca: CertificateAuthority,
    reverse_proxy_url: Option<String>,
    title_filters: Vec<TitleFilter>,
    mime_filters: Vec<String>,
    web: bool,
    state: Arc<State>,
    temp_dir: PathBuf,
}

impl Server {
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> Result<oneshot::Sender<()>> {
        info!("Starting HTTP(S) proxy server");
        std::fs::create_dir_all(&self.temp_dir)
            .with_context(|| format!("Failed to create temp dir '{}'", self.temp_dir.display()))?;
        let (stop_tx, stop_rx) = oneshot::channel();
        let (traffic_done_tx, mut traffic_done_rx) = mpsc::unbounded_channel();
        let server_cloned = self.clone();
        tokio::spawn(async move {
            let shutdown = Shutdown::new(async { stop_rx.await.unwrap_or_default() });
            let guard = shutdown.guard_weak();

            loop {
                tokio::select! {
                    res = listener.accept() => {
                        let Ok((cnx, _)) = res else {
                            continue;
                        };

                        let stream = TokioIo::new(cnx);
                        let traffic_done_tx = traffic_done_tx.clone();
                        let server_cloned = server_cloned.clone();
                        shutdown.spawn_task(async move {
                            let hyper_service = service_fn(move |request: hyper::Request<Incoming>| {
                                server_cloned.clone().handle(request, traffic_done_tx.clone())
                            });
                            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(stream, hyper_service)
                                .await;
                        });
                    }
                    _ = guard.cancelled() => {
                        break;
                    }
                }
            }
        });
        tokio::spawn(async move {
            while let Some((gid, raw_size)) = traffic_done_rx.recv().await {
                let state = self.state.clone();
                tokio::spawn(async move {
                    state.done_traffic(gid, raw_size).await;
                });
            }
        });
        Ok(stop_tx)
    }

    pub fn state(&self) -> Arc<State> {
        self.state.clone()
    }

    async fn handle(
        self: Arc<Self>,
        req: Request,
        traffic_done_tx: TrafficDoneSender,
    ) -> Result<Response, hyper::Error> {
        let req_uri = req.uri().to_string();
        let method = req.method().clone();

        let uri = if !req_uri.starts_with('/') || req_uri.starts_with(WEB_PREFIX) {
            req_uri.clone()
        } else if let Some(base_url) = &self.reverse_proxy_url {
            format!("{base_url}{req_uri}")
        } else {
            let mut res = Response::default();
            *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            set_res_body(&mut res, "No reserver proxy url");
            return Ok(res);
        };

        let path = match uri.split_once('?') {
            Some((v, _)) => v,
            None => uri.as_str(),
        };

        if let Some(path) = path.strip_prefix(CERT_PREFIX) {
            let mut res = Response::default();
            if let Err(err) = self.handle_cert_index(&mut res, path).await {
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                set_res_body(&mut res, err);
            };
            return Ok(res);
        } else if let Some(path) = path.strip_prefix(WEB_PREFIX) {
            let mut res = Response::default();
            if !self.web {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                set_res_body(
                    &mut res,
                    "The web interface is disabled. To enable it, run the command with the `--web` flag.",
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
            } else if path == "/subscribe/traffics" {
                self.handle_subscribe_traffics(&mut res).await
            } else if let Some(id) = path.strip_prefix("/subscribe/websocket/") {
                self.handle_subscribe_websocket(&mut res, id).await
            } else if path == "/traffics" {
                let query = req.uri().query().unwrap_or_default();
                self.handle_list_traffics(&mut res, query).await
            } else if let Some(id) = path.strip_prefix("/traffic/") {
                let query = req.uri().query().unwrap_or_default();
                self.handle_get_traffic(&mut res, id, query).await
            } else if let Some(path) = path.strip_prefix("/certificate/") {
                self.handle_cert_index(&mut res, path).await
            } else {
                *res.status_mut() = StatusCode::NOT_FOUND;
                return Ok(res);
            };
            if let Err(err) = ret {
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                set_res_body(&mut res, err);
            }
            return Ok(res);
        }

        let mut traffic = Traffic::new(&uri, method.as_str());

        traffic.check_match(is_match_title(
            &self.title_filters,
            &format!("{method} {uri}"),
        ));

        if method == Method::CONNECT {
            traffic.check_match(!self.title_filters.is_empty() || !self.mime_filters.is_empty());
            return self.handle_connect(req, traffic, traffic_done_tx);
        }

        traffic.set_req_headers(req.headers());

        if hyper_tungstenite::is_upgrade_request(&req) {
            let uri: Uri = uri.parse().expect("Invalid uri");
            return self
                .handle_upgrade_websocket(req, uri, traffic, traffic_done_tx.clone())
                .await;
        }

        let mut builder = hyper::Request::builder().uri(&uri).method(method.clone());

        for (key, value) in req.headers().iter() {
            if matches!(key, &HOST | &CONNECTION | &PROXY_AUTHORIZATION) {
                continue;
            }
            builder = builder.header(key.clone(), value.clone());
        }

        let req_body_file = if traffic.valid {
            match self.req_body_file(&mut traffic) {
                Ok(v) => Some(v),
                Err(err) => {
                    return self
                        .internal_server_error(err, traffic, traffic_done_tx)
                        .await;
                }
            }
        } else {
            None
        };

        let req_body = BodyWrapper::new(req.into_body(), req_body_file, None);

        let proxy_req = match builder.body(req_body) {
            Ok(v) => v,
            Err(err) => {
                return self
                    .internal_server_error(err, traffic, traffic_done_tx)
                    .await;
            }
        };

        traffic.set_start_time();
        let builder = Client::builder(TokioExecutor::new());
        let proxy_res = if uri.starts_with("https://") {
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
                return self
                    .internal_server_error(err, traffic, traffic_done_tx)
                    .await;
            }
        };

        self.process_proxy_res(proxy_res, traffic, traffic_done_tx)
            .await
    }

    async fn handle_cert_index(&self, res: &mut Response, path: &str) -> Result<()> {
        if path.is_empty() {
            set_res_body(res, CERT_INDEX);
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
        set_res_body(res, WEB_INDEX);
        res.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=UTF-8"),
        );
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        Ok(())
    }

    async fn handle_subscribe_traffics(&self, res: &mut Response) -> Result<()> {
        let (init_data, receiver) = (
            self.state.list_heads().await,
            self.state.subscribe_traffics(),
        );
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

    async fn handle_list_traffics(&self, res: &mut Response, format: &str) -> Result<()> {
        let (data, content_type) = self.state.export_all_traffics(format).await?;
        set_res_body(res, data);
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_str(content_type)?);
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        Ok(())
    }

    async fn handle_get_traffic(&self, res: &mut Response, id: &str, format: &str) -> Result<()> {
        let Ok(id) = id.parse() else {
            *res.status_mut() = StatusCode::BAD_REQUEST;
            set_res_body(res, "Invalid id");
            return Ok(());
        };
        let (data, content_type) = self.state.export_traffic(id, format).await?;
        set_res_body(res, data);
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_str(content_type)?);
        res.headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        Ok(())
    }

    async fn handle_subscribe_websocket(&self, res: &mut Response, id: &str) -> Result<()> {
        let Ok(id) = id.parse() else {
            *res.status_mut() = StatusCode::BAD_REQUEST;
            set_res_body(res, "Invalid id");
            return Ok(());
        };

        let Some((messages, receiver)) = self.state.subscribe_websocket(id).await else {
            *res.status_mut() = StatusCode::NOT_FOUND;
            set_res_body(res, "Not found websocket");
            return Ok(());
        };

        let stream = BroadcastStream::new(receiver);
        let stream = stream.filter_map(move |v| async move {
            match v {
                Ok((id_, message)) => {
                    if id_ != id {
                        None
                    } else {
                        Some(Ok(ndjson_frame(&message)))
                    }
                }
                Err(err) => Some(Err(anyhow!("{err}"))),
            }
        });

        let body = if messages.is_empty() {
            BodyExt::boxed(StreamBody::new(stream))
        } else {
            let init_stream = stream::iter(
                messages
                    .into_iter()
                    .map(|message| Ok(ndjson_frame(&message))),
            );
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

    async fn handle_upgrade_websocket(
        self: Arc<Self>,
        req: Request,
        uri: Uri,
        mut traffic: Traffic,
        traffic_done_tx: TrafficDoneSender,
    ) -> Result<Response, hyper::Error> {
        let mut req = {
            let (mut parts, _) = req.into_parts();

            parts.uri = {
                let mut parts = uri.into_parts();

                parts.scheme = if parts.scheme.unwrap_or(Scheme::HTTP) == Scheme::HTTP {
                    Some("ws".try_into().expect("Failed to convert scheme"))
                } else {
                    Some("wss".try_into().expect("Failed to convert scheme"))
                };

                match Uri::from_parts(parts) {
                    Ok(uri) => uri,
                    Err(err) => {
                        return self
                            .internal_server_error(
                                format!("Invalid uri, {err}"),
                                traffic,
                                traffic_done_tx,
                            )
                            .await;
                    }
                }
            };

            hyper::Request::from_parts(parts, ())
        };

        traffic.set_start_time();
        match hyper_tungstenite::upgrade(&mut req, None) {
            Ok((proxy_res, websocket)) => {
                let id = self.state.new_websocket().await;
                traffic.set_websocket_id(id);

                let server = self.clone();
                let fut = async move {
                    match websocket.await {
                        Ok(ws) => {
                            let server_cloned = server.clone();
                            if let Err(err) = server_cloned.handle_websocket(ws, req, id).await {
                                server
                                    .state
                                    .add_websocket_error(
                                        id,
                                        format!("Failed to handle WebSocket: {}", err),
                                    )
                                    .await;
                            }
                        }
                        Err(err) => {
                            server
                                .state
                                .add_websocket_error(
                                    id,
                                    format!("Failed to upgrade to WebSocket: {}", err),
                                )
                                .await;
                        }
                    }
                };

                tokio::spawn(fut);
                self.process_proxy_res(proxy_res, traffic, traffic_done_tx)
                    .await
            }
            Err(err) => {
                self.internal_server_error(
                    format!("Failed to upgrade to websocket, {err}"),
                    traffic,
                    traffic_done_tx,
                )
                .await
            }
        }
    }

    async fn handle_websocket(
        self: Arc<Self>,
        client_to_server_socket: WebSocketStream<TokioIo<Upgraded>>,
        req: hyper::Request<()>,
        id: usize,
    ) -> Result<()> {
        let (server_to_client_socket, _) = tokio_tungstenite::connect_async(req).await?;

        let (to_client_sink, from_client_stream) = client_to_server_socket.split();
        let (to_server_sink, from_server_stream) = server_to_client_socket.split();

        let server = self.clone();
        tokio::spawn(async move {
            server
                .handle_websocket_message(from_client_stream, to_server_sink, id, false)
                .await
        });

        tokio::spawn(async move {
            self.handle_websocket_message(from_server_stream, to_client_sink, id, true)
                .await
        });

        Ok(())
    }

    async fn handle_websocket_message(
        &self,
        mut stream: impl Stream<Item = Result<tungstenite::Message, tungstenite::Error>>
            + Unpin
            + Send
            + 'static,
        mut sink: impl Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin + Send + 'static,
        id: usize,
        server_to_client: bool,
    ) {
        while let Some(message) = stream.next().await {
            match message {
                Ok(message) => {
                    self.state
                        .add_websocket_message(id, &message, server_to_client)
                        .await;
                    if let Err(err) = sink.send(message).await {
                        if !ignore_tungstenite_error(&err) {
                            self.state
                                .add_websocket_error(id, format!("Websocket close error: {err}"))
                                .await
                        }
                    }
                }
                Err(err) => {
                    if ignore_tungstenite_error(&err) {
                        self.state
                            .add_websocket_error(id, "Closed".to_string())
                            .await;
                    } else {
                        self.state
                            .add_websocket_error(id, format!("Websocket message error: {err}"))
                            .await;
                    }
                    if let Err(err) = sink.send(tungstenite::Message::Close(None)).await {
                        if !ignore_tungstenite_error(&err) {
                            self.state
                                .add_websocket_error(id, format!("Websocket close error: {err}"))
                                .await
                        }
                    };

                    break;
                }
            }
        }
    }

    fn handle_connect(
        self: Arc<Self>,
        mut req: Request,
        mut traffic: Traffic,
        traffic_done_tx: TrafficDoneSender,
    ) -> Result<Response, hyper::Error> {
        let mut res = Response::default();
        let authority = match req.uri().authority().cloned() {
            Some(authority) => authority,
            None => {
                *res.status_mut() = StatusCode::BAD_REQUEST;
                return Ok(res);
            }
        };
        let server = self.clone();
        let fut = async move {
            match hyper::upgrade::on(&mut req).await {
                Ok(upgraded) => {
                    let mut upgraded = TokioIo::new(upgraded);

                    let mut buffer = [0; 4];
                    let bytes_read = match upgraded.read_exact(&mut buffer).await {
                        Ok(bytes_read) => bytes_read,
                        Err(err) => {
                            traffic.add_error(format!(
                                "Failed to read from upgraded connection: {err}"
                            ));
                            return;
                        }
                    };

                    let mut upgraded = Rewind::new_buffered(
                        upgraded,
                        bytes::Bytes::copy_from_slice(buffer[..bytes_read].as_ref()),
                    );

                    if buffer == *b"GET " {
                        if let Err(err) = self
                            .serve_connect_stream(
                                upgraded,
                                Scheme::HTTP,
                                authority,
                                traffic_done_tx,
                            )
                            .await
                        {
                            traffic.add_error(format!("Websocket connect error: {err}"));
                        }
                    } else if buffer[..2] == *b"\x16\x03" {
                        let server_config = match self.ca.gen_server_config(&authority).await {
                            Ok(server_config) => server_config,
                            Err(err) => {
                                traffic.add_error(format!("Failed to build server config: {err}"));
                                return;
                            }
                        };

                        let stream = match TlsAcceptor::from(server_config).accept(upgraded).await {
                            Ok(stream) => stream,
                            Err(err) => {
                                traffic.add_error(format!(
                                    "Failed to establish TLS Connection: {err}"
                                ));
                                return;
                            }
                        };

                        if let Err(err) = self
                            .serve_connect_stream(stream, Scheme::HTTPS, authority, traffic_done_tx)
                            .await
                        {
                            if !err
                                .to_string()
                                .starts_with("error shutting down connection")
                            {
                                traffic.add_error(format!("HTTPS connect error: {err}"));
                            }
                        }
                    } else {
                        traffic.add_error(format!(
                            "Unknown protocol, read '{:02X?}' from upgraded connection",
                            &buffer[..bytes_read]
                        ));

                        let mut server = match TcpStream::connect(authority.as_str()).await {
                            Ok(server) => server,
                            Err(err) => {
                                traffic
                                    .add_error(format! {"Failed to connect to {authority}: {err}"});
                                return;
                            }
                        };

                        if let Err(err) =
                            tokio::io::copy_bidirectional(&mut upgraded, &mut server).await
                        {
                            traffic.add_error(format!(
                                "Failed to tunnel unknown protocol to {}: {}",
                                authority, err
                            ));
                        }
                    }
                }
                Err(err) => {
                    traffic.add_error(format!("Upgrade error: {err}"));
                }
            };
            server.state.add_traffic(traffic).await;
        };

        tokio::spawn(fut);
        Ok(Response::default())
    }

    async fn serve_connect_stream<I>(
        self: Arc<Self>,
        stream: I,
        scheme: Scheme,
        authority: Authority,
        traffic_done_tx: TrafficDoneSender,
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

            self.clone().handle(req, traffic_done_tx.clone())
        });

        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection_with_upgrades(TokioIo::new(stream), service)
            .await
    }

    async fn process_proxy_res<T: Body<Data = Bytes> + Send + Sync + 'static>(
        &self,
        proxy_res: hyper::Response<T>,
        mut traffic: Traffic,
        traffic_done_tx: TrafficDoneSender,
    ) -> Result<Response, hyper::Error> {
        let proxy_res = {
            let (parts, body) = proxy_res.into_parts();
            Response::from_parts(parts, body.map_err(|_| anyhow!("Invalid response")).boxed())
        };

        let proxy_res_version = proxy_res.version();
        let proxy_res_status = proxy_res.status();
        let proxy_res_headers = proxy_res.headers().clone();

        let content_type = proxy_res_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();

        traffic.check_match(is_match_type(&self.mime_filters, content_type));

        let mut res = Response::default();

        let mut encoding = String::new();
        for (key, value) in proxy_res_headers.iter() {
            if key == CONTENT_ENCODING {
                encoding = value.to_str().map(|v| v.to_string()).unwrap_or_default();
            }
            res.headers_mut().insert(key.clone(), value.clone());
        }

        traffic
            .set_res_status(proxy_res_status)
            .set_http_version(&proxy_res_version)
            .set_res_headers(&proxy_res_headers);

        *res.status_mut() = proxy_res_status;

        let res_body_file = if traffic.valid {
            match self.res_body_file(&mut traffic, &encoding) {
                Ok(v) => Some(v),
                Err(err) => {
                    return self
                        .internal_server_error(err, traffic, traffic_done_tx)
                        .await;
                }
            }
        } else {
            None
        };

        let res_body = BodyWrapper::new(
            proxy_res.into_body(),
            res_body_file,
            Some((traffic.gid, traffic_done_tx)),
        );

        *res.body_mut() = BoxBody::new(res_body);

        self.state.add_traffic(traffic).await;

        Ok(res)
    }

    async fn internal_server_error<T: std::fmt::Display>(
        &self,
        error: T,
        mut traffic: Traffic,
        traffic_done_tx: TrafficDoneSender,
    ) -> Result<Response, hyper::Error> {
        let mut res = Response::default();
        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;

        let gid = traffic.gid;
        traffic.add_error(error.to_string());
        self.state.add_traffic(traffic).await;
        let _ = traffic_done_tx.send((gid, 0));

        Ok(res)
    }

    fn req_body_file(&self, traffic: &mut Traffic) -> Result<File> {
        let mime = extract_mime(&traffic.req_headers);
        let ext_name = to_ext_name(mime);
        let path = self
            .temp_dir
            .join(format!("{:05}-req{ext_name}", traffic.gid));
        let file = File::create(&path).with_context(|| {
            format!(
                "Failed to create file '{}' to store request body",
                path.display()
            )
        })?;
        traffic.set_req_body_file(&path);
        Ok(file)
    }

    fn res_body_file(&self, traffic: &mut Traffic, encoding: &str) -> Result<File> {
        let mime = extract_mime(&traffic.res_headers);
        let ext = to_ext_name(mime);
        let encoding_ext = match ENCODING_EXTS.iter().find(|(v, _)| *v == encoding) {
            Some((_, encoding_ext)) => encoding_ext,
            None => "",
        };
        let path = self
            .temp_dir
            .join(format!("{:05}-res{ext}{encoding_ext}", traffic.gid));
        let file = File::create(&path).with_context(|| {
            format!(
                "Failed to create file '{}' to store response body",
                path.display()
            )
        })?;
        traffic.set_res_body_file(&path);
        Ok(file)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PrintMode {
    Nothing,
    Oneline,
    #[default]
    Markdown,
}

pin_project! {
    pub struct BodyWrapper<B> {
        #[pin]
        inner: B,
        file: Option<File>,
        traffic_done: Option<(usize, TrafficDoneSender)>,
        raw_size: u64,
    }
    impl<B> PinnedDrop for BodyWrapper<B> {
        fn drop(this: Pin<&mut Self>) {
            if let Some((gid, traffic_done_tx)) = this.traffic_done.as_ref() {
                let _ = traffic_done_tx.send((*gid, this.raw_size));
            }
        }
     }
}

impl<B> BodyWrapper<B> {
    pub fn new(
        inner: B,
        file: Option<File>,
        traffic_done: Option<(usize, TrafficDoneSender)>,
    ) -> Self {
        Self {
            inner,
            file,
            traffic_done,
            raw_size: 0,
        }
    }
}

impl<B> Body for BodyWrapper<B>
where
    B: Body<Data = Bytes> + Send + Sync + 'static,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    if let Some(file) = this.file.as_mut() {
                        let _ = file.write_all(&data);
                    }
                    *this.raw_size += data.len() as u64;
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(e) => Poll::Ready(Some(Ok(e))),
            },
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn set_res_body<T: std::fmt::Display>(res: &mut Response, body: T) {
    let body = Bytes::from(body.to_string());
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

fn ignore_tungstenite_error(err: &tungstenite::Error) -> bool {
    matches!(
        err,
        tungstenite::Error::ConnectionClosed
            | tungstenite::Error::AlreadyClosed
            | tungstenite::Error::Protocol(
                tungstenite::error::ProtocolError::ResetWithoutClosingHandshake
            )
    )
}
