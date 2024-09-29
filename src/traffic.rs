use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http::{HeaderMap, StatusCode, Version};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::atomic::{self, AtomicUsize},
    time::Instant,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

static GLOBAL_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    pub gid: usize,
    pub uri: String,
    pub method: String,
    #[serde(serialize_with = "serialize_datetime")]
    pub start: OffsetDateTime,
    #[serde(skip)]
    pub record_time: Option<Instant>,
    pub time: Option<usize>,
    pub req_version: Option<String>,
    pub req_headers: Option<Headers>,
    pub req_body_file: Option<String>,
    pub status: Option<u16>,
    pub res_version: Option<String>,
    pub res_headers: Option<Headers>,
    pub res_body_file: Option<String>,
    pub res_body_size: Option<u64>,
    pub websocket_id: Option<usize>,
    pub error: Option<String>,
    #[serde(skip)]
    pub valid: bool,
}

impl Traffic {
    pub fn new(uri: &str, method: &str) -> Self {
        Self {
            gid: GLOBAL_ID.fetch_add(1, atomic::Ordering::Relaxed),
            uri: uri.to_string(),
            method: method.to_string(),
            start: OffsetDateTime::now_utc(),
            record_time: None,
            time: None,
            req_version: None,
            req_headers: None,
            req_body_file: None,
            status: None,
            res_version: None,
            res_headers: None,
            res_body_file: None,
            res_body_size: None,
            websocket_id: None,
            error: None,
            valid: true,
        }
    }

    pub fn add_error(&mut self, error: String) {
        match self.error.as_mut() {
            Some(current_error) => {
                current_error.push('\n');
                current_error.push_str(&error);
            }
            None => {
                self.error = Some(error);
            }
        }
    }

    pub fn oneline(&self) -> String {
        let mut output = format!("{} {}", self.method, self.uri,);
        if let Some(status) = self.status {
            output.push_str(&format!(" {}", status));
        }
        output
    }

    pub async fn markdown(&self) -> String {
        let (req_body, res_body) = self.bodies().await;

        let mut lines: Vec<String> = vec![];

        lines.push(format!("\n# {}", self.oneline()));

        if let Some(headers) = &self.req_headers {
            lines.push(render_header("REQUEST HEADERS", headers));
        }

        if let (Some(body), Some(body_file)) = (req_body, &self.req_body_file) {
            lines.push(render_body(
                "REQUEST BODY",
                &body,
                body_file,
                &self.req_headers,
            ));
        }

        if let Some(headers) = &self.res_headers {
            lines.push(render_header("RESPONSE HEADERS", headers));
        }

        if let (Some(body), Some(body_file)) = (res_body, &self.res_body_file) {
            lines.push(render_body(
                "RESPONSE BODY",
                &body,
                body_file,
                &self.res_headers,
            ));
        }

        if let Some(error) = &self.error {
            lines.push(render_error(error));
        }

        lines.join("\n\n")
    }

    pub async fn har(&self) -> Value {
        let entries = match self.har_entry().await {
            Some(v) => vec![v],
            None => vec![],
        };
        wrap_entries(entries)
    }

    pub async fn har_entry(&self) -> Option<Value> {
        self.status?;
        let (req_body, res_body) = self.bodies().await;
        let request = json!({
            "method": self.method,
            "url": self.uri,
            "httpVersion": self.req_version,
            "cookies": har_req_cookies(&self.req_headers),
            "headers": har_headers(&self.req_headers),
            "queryString": har_query_string(&self.uri),
            "postData": har_req_body(&req_body, &self.req_headers),
            "headersSize": har_size(self.req_headers.as_ref().map(|v| v.size), 0),
            "bodySize": har_size(req_body.as_ref().map(|v| v.size), 0),
        });
        let response = json!({
            "status": self.status.unwrap_or_default(),
            "statusText": "",
            "httpVersion": self.res_version,
            "cookies": har_res_cookies(&self.res_headers),
            "headers": har_headers(&self.res_headers),
            "content": har_res_body(&res_body, self.res_body_size.unwrap_or_default(), &self.res_headers),
            "redirectURL": get_header_value(&self.res_headers, "location").unwrap_or_default(),
            "headersSize": har_size(self.res_headers.as_ref().map(|v| v.size), -1),
            "bodySize": har_size(self.res_body_size, -1),
        });
        Some(json!({
            "startedDateTime": self.start.format(&Rfc3339).unwrap_or_default(),
            "time": self.time.map(|v| v as isize).unwrap_or(-1),
            "request": request,
            "response": response,
            "cache": {},
            "timings": {
                "connect": -1,
                "ssl": -1,
                "send": -1,
                "receive": -1,
                "wait": -1
            }
        }))
    }

    pub async fn curl(&self) -> String {
        let req_body = Body::read(&self.req_body_file).await;

        let mut output = format!("curl {}", self.uri);
        let escape_single_quote = |v: &str| v.replace('\'', r#"'\''"#);
        if self.method != "GET" {
            output.push_str(&format!(" \\\n  -X {}", self.method));
        }
        let headers = match &self.req_headers {
            Some(headers) => headers.items.as_slice(),
            None => &[],
        };
        for header in headers {
            if ["content-length", "host"].contains(&header.name.as_str()) {
                continue;
            }
            output.push_str(&format!(
                " \\\n  -H '{}: {}'",
                header.name,
                escape_single_quote(&header.value)
            ))
        }
        if let Some(body) = req_body {
            if body.is_utf8() {
                output.push_str(&format!(" \\\n  -d '{}'", escape_single_quote(&body.value)))
            } else {
                output.push_str(" \\\n  --data-binary @-");
                output = format!(
                    "echo {} | \\\n  base64 --decode | \\\n  {}",
                    body.value, output
                );
            }
        }
        output
    }

    pub async fn json(&self) -> Value {
        let mut value = json!(self);
        let (req_body, res_body) = self.bodies().await;
        value["req_body"] = json!(req_body);
        value["res_body"] = json!(res_body);
        value
    }

    pub async fn export(&self, format: &str) -> Result<(String, &'static str)> {
        match format {
            "markdown" => Ok((self.markdown().await, "text/markdown; charset=UTF-8")),
            "har" => Ok((
                serde_json::to_string_pretty(&self.har().await)?,
                "application/json; charset=UTF-8",
            )),
            "curl" => Ok((self.curl().await, "text/plain; charset=UTF-8")),
            "" => Ok((
                serde_json::to_string_pretty(&self.json().await)?,
                "application/json; charset=UTF-8",
            )),
            _ => bail!("Unsupported format: {}", format),
        }
    }

    pub(crate) fn head(&self, id: usize) -> TrafficHead {
        TrafficHead {
            id,
            method: self.method.clone(),
            uri: self.uri.clone(),
            status: self.status,
            size: self.res_body_size,
            time: self.time,
            mime: extract_mime(&self.res_headers).to_string(),
        }
    }

    pub(crate) fn set_req_version(&mut self, http_version: &Version) -> &mut Self {
        self.req_version = Some(format!("{http_version:?}"));
        self
    }

    pub(crate) fn set_req_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.req_headers = Some(Headers::new(headers));
        self
    }

    pub(crate) fn set_req_body_file(&mut self, path: &Path) -> &mut Self {
        self.req_body_file = Some(path.display().to_string());
        self
    }

    pub(crate) fn set_res_status(&mut self, status: StatusCode) -> &mut Self {
        self.status = Some(status.into());
        self
    }

    pub(crate) fn set_res_version(&mut self, http_version: &Version) -> &mut Self {
        self.res_version = Some(format!("{http_version:?}"));
        self
    }

    pub(crate) fn set_res_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.res_headers = Some(Headers::new(headers));
        self
    }

    pub(crate) fn set_res_body_file(&mut self, path: &Path) -> &mut Self {
        self.res_body_file = Some(path.display().to_string());
        self
    }

    pub(crate) fn set_websocket_id(&mut self, id: usize) -> &mut Self {
        self.websocket_id = Some(id);
        self
    }

    pub(crate) fn check_match(&mut self, is_match: bool) -> &mut Self {
        self.valid = self.valid && is_match;
        self
    }

    pub(crate) fn start_record_time(&mut self) {
        self.record_time = Some(Instant::now());
    }

    pub(crate) fn done_res_body(&mut self, id: usize, raw_size: u64) -> TrafficHead {
        if raw_size == 0 {
            self.res_body_file = None;
        }
        if self.error.is_none() {
            if let Some(instant) = self.record_time.take() {
                self.time = Some(instant.elapsed().as_millis() as usize);
            }
            self.res_body_size = Some(raw_size);
        }
        self.record_time = None;
        self.head(id)
    }

    pub(crate) async fn bodies(&self) -> (Option<Body>, Option<Body>) {
        tokio::join!(
            Body::read(&self.req_body_file),
            Body::read(&self.res_body_file)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficHead {
    pub id: usize,
    pub method: String,
    pub uri: String,
    pub status: Option<u16>,
    pub size: Option<u64>,
    pub time: Option<usize>,
    pub mime: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Headers {
    pub items: Vec<Header>,
    pub size: u64,
}

impl Headers {
    pub fn new(headers: &HeaderMap) -> Self {
        Self {
            items: map_headers(headers),
            size: cal_headers_size(headers),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: &str, value: &str) -> Self {
        Self {
            name: name.to_string(),
            value: value.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Body {
    pub encode: String,
    pub value: String,
    pub size: u64,
}

impl Body {
    pub async fn read(path: &Option<String>) -> Option<Self> {
        let path = path.as_ref()?;
        let data = tokio::fs::read(path).await.ok()?;
        if data.is_empty() {
            return None;
        }
        Some(Self::bytes(&data))
    }

    pub fn bytes(data: &[u8]) -> Self {
        let size = data.len();
        match std::str::from_utf8(data) {
            Ok(value) => Body {
                encode: "utf8".to_string(),
                value: value.to_string(),
                size: size as _,
            },
            Err(_) => Body {
                encode: "base64".to_string(),
                value: STANDARD.encode(data),
                size: size as _,
            },
        }
    }

    pub fn text(value: &str) -> Self {
        Body {
            encode: "utf8".to_string(),
            value: value.to_string(),
            size: value.len() as _,
        }
    }

    pub fn is_utf8(&self) -> bool {
        self.encode == "utf8"
    }
}

fn render_header(title: &str, headers: &Headers) -> String {
    let value = headers
        .items
        .iter()
        .map(|header| format!("{}: {}", header.name, header.value))
        .collect::<Vec<String>>()
        .join("\n");
    format!(
        r#"{title}
```
{value}
```"#
    )
}

pub(crate) fn render_body(
    title: &str,
    body: &Body,
    body_path: &str,
    headers: &Option<Headers>,
) -> String {
    let content_type = extract_mime(headers);
    if body.is_utf8() {
        let body_value = &body.value;
        let lang = to_md_lang(content_type);
        format!(
            r#"{title}
```{lang}
{body_value}
```"#
        )
    } else {
        format!("{title}\n\n[BINARY DATA]({body_path})")
    }
}

fn render_error(error: &str) -> String {
    if error.contains('\n') {
        format!(
            r#"ERROR
```
{}
```"#,
            error
        )
    } else {
        format!("ERROR: {}", error)
    }
}

fn har_headers(headers: &Option<Headers>) -> Value {
    match headers {
        Some(headers) => headers.items.iter().map(|header| json!(header)).collect(),
        None => json!([]),
    }
}

fn har_size(size: Option<u64>, default_value: i64) -> i64 {
    size.map(|v| v as i64).unwrap_or(default_value)
}

fn har_query_string(url: &str) -> Value {
    match url::Url::parse(url) {
        Ok(url) => url
            .query_pairs()
            .into_iter()
            .map(|(k, v)| json!({ "name": &k, "value": &v }))
            .collect(),
        Err(_) => json!([]),
    }
}

fn har_req_cookies(headers: &Option<Headers>) -> Value {
    match headers {
        Some(headers) => headers
            .items
            .iter()
            .filter(|header| header.name == "cookie")
            .flat_map(|header| {
                header
                    .value
                    .split(';')
                    .map(|v| v.trim())
                    .collect::<Vec<&str>>()
            })
            .filter_map(|value| {
                value
                    .split_once('=')
                    .map(|(k, v)| json!({ "name": k, "value": v }))
            })
            .collect(),
        None => json!([]),
    }
}

fn har_req_body(body: &Option<Body>, headers: &Option<Headers>) -> Value {
    let content_type = get_header_value(headers, "content-type").unwrap_or_default();
    match body {
        Some(body) => json!({"mimeType": content_type, "text": body.value}),
        None => json!({"mimeType": content_type, "text": ""}),
    }
}

fn har_res_body(body: &Option<Body>, raw_size: u64, headers: &Option<Headers>) -> Value {
    let content_type = get_header_value(headers, "content-type").unwrap_or_default();
    match body {
        Some(body) => {
            let mut value = json!({"size": raw_size, "mimeType": content_type, "text": body.value});
            if !body.is_utf8() {
                value["encoding"] = "base64".into();
            }
            value["compression"] = (body.size as isize - raw_size as isize).into();
            value
        }
        None => json!({"size": 0, "mimeType": content_type, "text": ""}),
    }
}

fn har_res_cookies(headers: &Option<Headers>) -> Value {
    match headers {
        Some(headers) => headers
            .items
            .iter()
            .filter(|header| header.name.as_str() == "set-cookie")
            .filter_map(|header| {
                cookie::Cookie::parse(&header.value).ok().map(|cookie| {
                    let mut json_cookie =
                        json!({ "name": cookie.name(), "value": cookie.value(), });
                    if let Some(value) = cookie.path() {
                        json_cookie["path"] = value.into();
                    }
                    if let Some(value) = cookie.domain() {
                        json_cookie["domain"] = value.into();
                    }
                    if let Some(cookie::Expiration::DateTime(datetime)) = cookie.expires() {
                        if let Ok(datetime) =
                            datetime.format(&time::format_description::well_known::Rfc3339)
                        {
                            json_cookie["expires"] = datetime.into();
                        }
                    }
                    if let Some(value) = cookie.http_only() {
                        json_cookie["httpOnly"] = value.into();
                    }
                    if let Some(value) = cookie.secure() {
                        json_cookie["secure"] = value.into();
                    }
                    json_cookie
                })
            })
            .collect(),
        None => json!([]),
    }
}

pub(crate) fn extract_mime(headers: &Option<Headers>) -> &str {
    get_header_value(headers, "content-type")
        .map(|v| match v.split_once(';') {
            Some((v, _)) => v.trim(),
            None => v,
        })
        .unwrap_or_default()
}

fn get_header_value<'a>(headers: &'a Option<Headers>, key: &str) -> Option<&'a str> {
    headers.as_ref().and_then(|v| {
        v.items
            .iter()
            .find(|header| header.name == key)
            .map(|header| header.value.as_str())
    })
}

pub(crate) fn to_ext_name(mime: &str) -> &str {
    match mime {
        "audio/aac" => ".aac",
        "application/x-abiword" => ".abw",
        "image/apng" => ".apng",
        "application/x-freearc" => ".arc",
        "image/avif" => ".avif",
        "video/x-msvideo" => ".avi",
        "application/vnd.amazon.ebook" => ".azw",
        "application/octet-stream" => ".bin",
        "image/bmp" => ".bmp",
        "application/x-bzip" => ".bz",
        "application/x-bzip2" => ".bz2",
        "application/x-cdf" => ".cda",
        "application/x-csh" => ".csh",
        "text/css" => ".css",
        "text/csv" => ".csv",
        "application/msword" => ".doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => ".docx",
        "application/vnd.ms-fontobject" => ".eot",
        "application/epub+zip" => ".epub",
        "application/gzip" | "application/x-gzip" => ".gz",
        "image/gif" => ".gif",
        "text/html" | "text/htm" => ".html",
        "image/vnd.microsoft.icon" => ".ico",
        "text/calendar" => ".ics",
        "application/java-archive" => ".jar",
        "image/jpeg" => ".jpeg",
        "text/javascript" => ".js",
        "application/json" => ".json",
        "application/ld+json" => ".jsonld",
        "audio/midi" | "audio/x-midi" => ".mid",
        "audio/mpeg" => ".mp3",
        "video/mp4" => ".mp4",
        "video/mpeg" => ".mpeg",
        "application/vnd.apple.installer+xml" => ".mpkg",
        "application/vnd.oasis.opendocument.presentation" => ".odp",
        "application/vnd.oasis.opendocument.spreadsheet" => ".ods",
        "application/vnd.oasis.opendocument.text" => ".odt",
        "audio/ogg" => ".oga",
        "video/ogg" => ".ogv",
        "application/ogg" => ".ogx",
        "font/otf" => ".otf",
        "image/png" => ".png",
        "application/pdf" => ".pdf",
        "application/x-httpd-php" => ".php",
        "application/vnd.ms-powerpoint" => ".ppt",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => ".pptx",
        "application/vnd.rar" => ".rar",
        "application/rtf" => ".rtf",
        "application/x-sh" => ".sh",
        "image/svg+xml" => ".svg",
        "application/x-tar" => ".tar",
        "image/tiff" => ".tif",
        "video/mp2t" => ".ts",
        "font/ttf" => ".ttf",
        "text/plain" => ".txt",
        "application/vnd.visio" => ".vsd",
        "audio/wav" => ".wav",
        "audio/webm" => ".weba",
        "video/webm" => ".webm",
        "image/webp" => ".webp",
        "font/woff" => ".woff",
        "font/woff2" => ".woff2",
        "application/xhtml+xml" => ".xhtml",
        "application/vnd.ms-excel" => ".xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => ".xlsx",
        "application/xml" | "text/xml" => ".xml",
        "application/vnd.mozilla.xul+xml" => ".xul",
        "application/zip" | "x-zip-compressed" => ".zip",
        "video/3gpp" | "audio/3gpp" => ".3gp",
        "video/3gpp2" | "audio/3gpp2" => ".3g2",
        "application/x-7z-compressed" => ".7z",
        _ => {
            if mime.starts_with("text/") {
                ".txt"
            } else {
                ""
            }
        }
    }
}

pub(crate) fn to_md_lang(mime: &str) -> &str {
    if let Some(value) = mime
        .strip_prefix("text/")
        .or_else(|| mime.strip_prefix("application/"))
    {
        if let Some(value) = value.strip_prefix("x-") {
            value
        } else {
            value
        }
    } else {
        ""
    }
}

pub(crate) fn wrap_entries(entries: Vec<Value>) -> Value {
    json!({
        "log": {
            "version": "1.2",
            "creator": {
                "name": "proxyfor",
                "version": env!("CARGO_PKG_VERSION"),
                "comment": "",
            },
            "pages": [],
            "entries": entries,
        }
    })
}

pub(crate) fn serialize_datetime<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = date.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&formatted)
}

fn map_headers(headers: &HeaderMap) -> Vec<Header> {
    headers
        .iter()
        .map(|(key, value)| Header::new(key.as_str(), value.to_str().unwrap_or_default()))
        .collect()
}

fn cal_headers_size(headers: &HeaderMap) -> u64 {
    headers
        .iter()
        .map(|(key, value)| {
            key.as_str().as_bytes().len() as u64 + value.as_bytes().len() as u64 + 12
        })
        .sum::<u64>()
        + 7
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderName, HeaderValue};
    use pretty_assertions::assert_eq;

    fn create_headers(values: &[(&str, &str)]) -> Headers {
        let mut headers = HeaderMap::new();

        for (key, value) in values {
            let header_name = HeaderName::from_bytes(key.as_bytes()).unwrap();
            let header_value = HeaderValue::from_str(value).unwrap();
            headers.insert(header_name, header_value);
        }

        Headers::new(&headers)
    }

    #[test]
    fn test_render_body() {
        let body = Body::bytes(&[
            0x6b, 0x4e, 0x1a, 0xc3, 0xaf, 0x03, 0xd2, 0x1e, 0x7e, 0x73, 0xba, 0xc8, 0xbd, 0x84,
            0x0f, 0x83,
        ]);
        let output = render_body(
            "RESPONSE BODY",
            &body,
            "/tmp/proxyfor-666/1-res",
            &Some(create_headers(&[(
                "content-type",
                "application/octet-stream",
            )])),
        );
        let expect = r#"RESPONSE BODY

[BINARY DATA](/tmp/proxyfor-666/1-res)"#;
        assert_eq!(output, expect);
    }

    #[test]
    fn test_md_lang() {
        assert_eq!(to_md_lang("application/json"), "json");
        assert_eq!(to_md_lang("application/xml"), "xml");
        assert_eq!(to_md_lang("application/octet-stream"), "octet-stream");
        assert_eq!(to_md_lang("application/javascript"), "javascript");
        assert_eq!(to_md_lang("text/x-rust"), "rust");
        assert_eq!(to_md_lang("text/css"), "css");
    }
}
