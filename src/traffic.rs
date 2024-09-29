use anyhow::{bail, Result};
use async_compression::tokio::write::{BrotliDecoder, DeflateDecoder, GzipDecoder, ZstdDecoder};
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
use tokio::io::AsyncWriteExt;

const HEX_VIEW_SIZE: usize = 320;
static TRAFFIC_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    pub id: usize,
    pub uri: String,
    pub method: String,
    #[serde(serialize_with = "serialize_datetime")]
    pub start: OffsetDateTime,
    #[serde(skip)]
    pub record_time: Option<Instant>,
    pub time: Option<usize>,
    pub req_version: Option<String>,
    pub req_headers: Option<Headers>,
    #[serde(skip)]
    pub req_body_file: Option<String>,
    pub status: Option<u16>,
    pub res_version: Option<String>,
    pub res_headers: Option<Headers>,
    #[serde(skip)]
    pub res_body_file: Option<String>,
    #[serde(skip)]
    pub size: Option<usize>,
    pub websocket_id: Option<usize>,
    pub error: Option<String>,
    #[serde(skip)]
    pub valid: bool,
}

impl Traffic {
    pub fn new(uri: &str, method: &str) -> Self {
        Self {
            id: TRAFFIC_ID.fetch_add(1, atomic::Ordering::Relaxed),
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
            size: None,
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

    pub async fn markdown(&self, print: bool) -> String {
        let req_body = self.read_req_body().await;
        let res_body = self.read_res_body().await;

        let mut lines: Vec<String> = vec![];

        lines.push(format!("\n# {}", self.oneline()));

        if let Some(headers) = &self.req_headers {
            lines.push(render_header("REQUEST HEADERS", headers));
        }

        if let Some(body) = req_body {
            if !body.is_empty() {
                lines.push(render_body("REQUEST BODY", &body, &self.req_headers, print));
            }
        }

        if let Some(headers) = &self.res_headers {
            lines.push(render_header("RESPONSE HEADERS", headers));
        }

        if let Some(body) = res_body {
            if !body.is_empty() {
                lines.push(render_body(
                    "RESPONSE BODY",
                    &body,
                    &self.res_headers,
                    print,
                ));
            }
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
        let req_body = self.read_req_body().await;
        let res_body = self.read_res_body().await;
        let request = json!({
            "method": self.method,
            "url": self.uri,
            "httpVersion": self.req_version,
            "cookies": har_req_cookies(&self.req_headers),
            "headers": har_headers(&self.req_headers),
            "queryString": har_query_string(&self.uri),
            "postData": har_req_body(&req_body, &self.req_headers),
            "headersSize": har_size(&self.req_headers.as_ref().map(|v| v.size)),
            "bodySize": har_size(&req_body.as_ref().map(|v| v.raw_size)),
        });
        let response = json!({
            "status": self.status.unwrap_or_default(),
            "statusText": "",
            "httpVersion": self.res_version,
            "cookies": har_res_cookies(&self.res_headers),
            "headers": har_headers(&self.res_headers),
            "content": har_res_body(&res_body, &self.res_headers),
            "redirectURL": get_header_value(&self.res_headers, "location").unwrap_or_default(),
            "headersSize": har_size(&self.res_headers.as_ref().map(|v| v.size)),
            "bodySize": har_size(&res_body.as_ref().map(|v| v.raw_size)),
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
        let req_body = self.read_req_body().await;
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
            if header.name != "content-length" {
                output.push_str(&format!(
                    " \\\n  -H '{}: {}'",
                    header.name,
                    escape_single_quote(&header.value)
                ))
            }
        }
        if let Some(body) = req_body {
            if !body.is_empty() {
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
        }
        output
    }

    pub async fn json(&self) -> Value {
        let mut value = json!(self);
        let req_body = self.read_req_body().await;
        let res_body = self.read_res_body().await;
        value["req_body"] = json!(req_body);
        value["res_body"] = json!(res_body);
        value
    }

    pub async fn export(&self, format: &str) -> Result<(String, &'static str)> {
        match format {
            "markdown" => Ok((self.markdown(false).await, "text/markdown; charset=UTF-8")),
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

    pub(crate) fn head(&self) -> TrafficHead {
        TrafficHead {
            id: self.id,
            method: self.method.clone(),
            uri: self.uri.clone(),
            status: self.status,
            size: self.size,
            time: self.time,
            mime: extract_content_type(&self.res_headers).map(|v| v.to_string()),
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

    pub(crate) async fn done_record_time(&mut self) -> TrafficHead {
        if let Some(instant) = self.record_time.take() {
            self.time = Some(instant.elapsed().as_millis() as usize);
        }
        let res_body = self.read_res_body().await;
        self.size = res_body.as_ref().map(|v| v.raw_size);
        self.head()
    }

    pub async fn read_req_body(&self) -> Option<Body> {
        let path = self.req_body_file.as_ref()?;
        Body::read(path, "").await.ok()
    }

    pub async fn read_res_body(&self) -> Option<Body> {
        let path = self.res_body_file.as_ref()?;
        let encoding = get_header_value(&self.res_headers, "content-encoding").unwrap_or_default();
        Body::read(path, encoding).await.ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficHead {
    pub id: usize,
    pub method: String,
    pub uri: String,
    pub status: Option<u16>,
    pub size: Option<usize>,
    pub time: Option<usize>,
    pub mime: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Headers {
    pub items: Vec<Header>,
    pub size: usize,
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
    pub raw_size: usize,
    pub size: usize,
}

impl Body {
    pub async fn read(path: &str, encoding: &str) -> Result<Self> {
        let raw_data = tokio::fs::read(path).await?;
        let data = decompress(&raw_data, encoding).await?;
        Ok(Self::bytes(&data, raw_data.len()))
    }

    pub fn bytes(data: &[u8], raw_size: usize) -> Self {
        let size = data.len();
        match std::str::from_utf8(data) {
            Ok(value) => Body {
                encode: "utf8".to_string(),
                value: value.to_string(),
                raw_size,
                size,
            },
            Err(_) => Body {
                encode: "base64".to_string(),
                value: STANDARD.encode(data),
                raw_size,
                size,
            },
        }
    }

    pub fn text(value: &str, raw_size: usize) -> Self {
        Body {
            encode: "utf8".to_string(),
            value: value.to_string(),
            raw_size,
            size: value.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
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

fn render_body(title: &str, body: &Body, headers: &Option<Headers>, print: bool) -> String {
    let content_type = extract_content_type(headers).unwrap_or_default();
    if body.is_utf8() {
        let body_value = &body.value;
        let lang = md_lang(content_type);
        format!(
            r#"{title}
```{lang}
{body_value}
```"#
        )
    } else if print {
        let Ok(bytes) = STANDARD.decode(&body.value) else {
            return String::new();
        };
        let body_bytes = if bytes.len() > HEX_VIEW_SIZE * 2 {
            let dots = "⋅".repeat(67);
            format!(
                "{}\n{}\n{}",
                render_bytes(&bytes[0..HEX_VIEW_SIZE]),
                dots,
                render_bytes(&bytes[bytes.len() - HEX_VIEW_SIZE..]),
            )
        } else {
            render_bytes(&bytes).to_string()
        };
        format!(
            r#"{title}
```
{body_bytes}
```"#
        )
    } else {
        let body_value = &body.value;
        format!(
            r#"{title}
```
data:{content_type};base64,{body_value}
```"#
        )
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

fn render_bytes(source: &[u8]) -> String {
    let config = pretty_hex::HexConfig {
        title: false,
        chunk: 2,
        ..Default::default()
    };

    pretty_hex::config_hex(&source, config)
}

fn har_headers(headers: &Option<Headers>) -> Value {
    match headers {
        Some(headers) => headers.items.iter().map(|header| json!(header)).collect(),
        None => json!([]),
    }
}

fn har_size(size: &Option<usize>) -> isize {
    size.map(|v| v as isize).unwrap_or(-1)
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

fn har_res_body(body: &Option<Body>, headers: &Option<Headers>) -> Value {
    let content_type = get_header_value(headers, "content-type").unwrap_or_default();
    match body {
        Some(body) => {
            let size = body.size;
            let raw_size = body.raw_size;
            let mut value = json!({"size": har_size(&Some(raw_size)), "mimeType": content_type, "text": body.value});
            if !body.is_utf8() {
                value["encoding"] = "base64".into();
            }
            value["compression"] = (size as isize - raw_size as isize).into();
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

fn extract_content_type(headers: &Option<Headers>) -> Option<&str> {
    get_header_value(headers, "content-type").map(|v| match v.split_once(';') {
        Some((v, _)) => v.trim(),
        None => v,
    })
}

fn get_header_value<'a>(headers: &'a Option<Headers>, key: &str) -> Option<&'a str> {
    headers.as_ref().and_then(|v| {
        v.items
            .iter()
            .find(|header| header.name == key)
            .map(|header| header.value.as_str())
    })
}

fn md_lang(content_type: &str) -> &str {
    if let Some(value) = content_type
        .strip_prefix("text/")
        .or_else(|| content_type.strip_prefix("application/"))
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

async fn decompress(data: &[u8], encoding: &str) -> Result<Vec<u8>> {
    match encoding {
        "deflate" => decompress_deflate(data).await,
        "gzip" => decompress_gzip(data).await,
        "br" => decompress_br(data).await,
        "zstd" => decompress_zstd(data).await,
        _ => Ok(data.to_vec()),
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
decompress_fn!(decompress_zstd, ZstdDecoder);

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

fn cal_headers_size(headers: &HeaderMap) -> usize {
    headers
        .iter()
        .map(|(key, value)| key.as_str().as_bytes().len() + value.as_bytes().len() + 12)
        .sum::<usize>()
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
        let body = Body::bytes(
            &[
                0x6b, 0x4e, 0x1a, 0xc3, 0xaf, 0x03, 0xd2, 0x1e, 0x7e, 0x73, 0xba, 0xc8, 0xbd, 0x84,
                0x0f, 0x83,
            ],
            16,
        );
        let output = render_body(
            "REQUEST BODY",
            &body,
            &Some(create_headers(&[(
                "content-type",
                "application/octet-stream",
            )])),
            false,
        );
        let expect = r#"REQUEST BODY
```
data:application/octet-stream;base64,a04aw68D0h5+c7rIvYQPgw==
```"#;
        assert_eq!(output, expect);
    }

    #[test]
    fn test_render_body_print() {
        let body = Body::bytes(
            &[
                0x6b, 0x4e, 0x1a, 0xc3, 0xaf, 0x03, 0xd2, 0x1e, 0x7e, 0x73, 0xba, 0xc8, 0xbd, 0x84,
                0x0f, 0x83,
            ],
            16,
        );
        let output = render_body(
            "REQUEST BODY",
            &body,
            &Some(create_headers(&[("content-type", "plain/text")])),
            true,
        );
        let expect = r#"REQUEST BODY
```
0000:   6b4e 1ac3 af03 d21e  7e73 bac8 bd84 0f83   kN......~s......
```"#;
        assert_eq!(output, expect);
    }

    #[test]
    fn test_md_lang() {
        assert_eq!(md_lang("application/json"), "json");
        assert_eq!(md_lang("application/xml"), "xml");
        assert_eq!(md_lang("application/octet-stream"), "octet-stream");
        assert_eq!(md_lang("application/javascript"), "javascript");
        assert_eq!(md_lang("text/x-rust"), "rust");
        assert_eq!(md_lang("text/css"), "css");
    }
}
