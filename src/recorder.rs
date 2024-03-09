use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use indexmap::IndexMap;
use serde::{Serialize, Serializer};
use std::borrow::Cow;

const HEX_VIEW_SIZE: usize = 320;

#[derive(Debug)]
pub struct Recorder {
    traffic: Traffic,
    should_dump: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    uri: String,
    method: String,
    req_headers: Option<Headers>,
    #[serde(serialize_with = "serialize_optional_bytes")]
    req_body: Option<Bytes>,
    res_status: Option<u16>,
    res_headers: Option<Headers>,
    #[serde(serialize_with = "serialize_optional_bytes")]
    res_body: Option<Bytes>,
    error: Option<String>,
}

pub type Headers = IndexMap<String, String>;

impl Recorder {
    pub fn new(uri: &str, method: &str) -> Self {
        let traffic = Traffic::new(uri, method);
        Self {
            traffic,
            should_dump: true,
        }
    }

    // Remove the unused functions
    pub fn set_req_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.traffic.req_headers = Some(convert_headers(headers));
        self
    }

    pub fn set_req_body(&mut self, body: Bytes) -> &mut Self {
        if body.is_empty() {
            self
        } else {
            self.traffic.req_body = Some(body);
            self
        }
    }

    pub fn set_res_status(&mut self, status: StatusCode) -> &mut Self {
        self.traffic.res_status = Some(status.into());
        self
    }

    pub fn set_res_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.traffic.res_headers = Some(convert_headers(headers));
        self
    }

    pub fn set_res_body(&mut self, body: Bytes) -> &mut Self {
        if body.is_empty() {
            self
        } else {
            self.traffic.res_body = Some(body);
            self
        }
    }

    pub fn add_error(&mut self, error: String) -> &mut Self {
        self.traffic.add_error(error);
        self
    }

    pub fn control_dump(&mut self, should_dump: bool) -> &mut Self {
        self.should_dump = self.should_dump && should_dump;
        self
    }

    pub fn take_traffic(self) -> Traffic {
        self.traffic
    }

    pub fn print(&self) {
        if self.should_dump {
            println!("{}", self.traffic.to_markdown());
        }
    }
}

impl Traffic {
    pub fn new(uri: &str, method: &str) -> Self {
        Self {
            uri: uri.to_string(),
            method: method.to_string(),
            req_headers: None,
            req_body: None,
            res_status: None,
            res_headers: None,
            res_body: None,
            error: None,
        }
    }

    pub fn add_error(&mut self, error: String) {
        match self.error.as_mut() {
            Some(current_error) => current_error.push_str(&error),
            None => {
                self.error = Some(error);
            }
        }
    }

    pub fn head(&self) -> (&str, &str) {
        (&self.method, &self.uri)
    }

    pub fn to_markdown(&self) -> String {
        let mut lines: Vec<String> = vec![];
        lines.push(format!("\n# {} {}", self.method, self.uri));

        if let Some(headers) = &self.req_headers {
            lines.push(render_header("REQUEST HEADERS", headers));
        }

        if let Some(body) = &self.req_body {
            lines.push(render_body("REQUEST BODY", body, &self.req_headers));
        }

        if let Some(status) = &self.res_status {
            lines.push(format!("RESPONSE STATUS: {status}"));
        }

        if let Some(headers) = &self.res_headers {
            lines.push(render_header("RESPONSE HEADERS", headers));
        }

        if let Some(body) = &self.res_body {
            lines.push(render_body("RESPONSE BODY", body, &self.res_headers));
        }

        if let Some(error) = &self.error {
            lines.push(render_error(error));
        }
        lines.join("\n\n")
    }
}

#[derive(Debug)]
pub(crate) struct ErrorRecorder {
    recorder: Recorder,
}

impl ErrorRecorder {
    pub fn new(reocorder: Recorder) -> Self {
        Self {
            recorder: reocorder,
        }
    }

    pub fn add_error(&mut self, error: String) -> &mut Self {
        self.recorder.add_error(error);
        self
    }
}

impl Drop for ErrorRecorder {
    fn drop(&mut self) {
        self.recorder.print();
    }
}

fn render_header(title: &str, headers: &Headers) -> String {
    let value = headers
        .iter()
        .map(|(key, value)| format!("{key}: {value}"))
        .collect::<Vec<String>>()
        .join("\n");
    format!(
        r#"{title}
```
{value}
```"#
    )
}

fn render_body(title: &str, body: &Bytes, headers: &Option<Headers>) -> String {
    let (body, is_utf8) = render_bytes(body);
    let lang = recognize_lang(is_utf8, headers);
    format!(
        r#"{title}
```{lang}
{body}
```"#
    )
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

fn render_bytes(data: &[u8]) -> (String, bool) {
    if let Ok(value) = std::str::from_utf8(data) {
        (value.to_string(), true)
    } else if data.len() > HEX_VIEW_SIZE * 2 {
        let value = format!(
            "{}\n......\n{}",
            hexplay::HexView::new(&data[0..HEX_VIEW_SIZE]),
            hexplay::HexView::new(&data[data.len() - HEX_VIEW_SIZE..])
        );
        (value, false)
    } else {
        let value = hexplay::HexView::new(data).to_string();
        (value, false)
    }
}

fn recognize_lang(is_utf8: bool, headers: &Option<Headers>) -> &str {
    if !is_utf8 {
        return "";
    }
    headers
        .as_ref()
        .and_then(|v| v.get("content-type"))
        .map(|v| md_lang(v))
        .unwrap_or_default()
}

fn md_lang(content_type: &str) -> &str {
    let content_type = match content_type.split_once(';') {
        Some((v, _)) => v.trim(),
        None => content_type,
    };
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

fn convert_headers(headers: &HeaderMap) -> IndexMap<String, String> {
    headers
        .iter()
        .map(|(key, value)| {
            (
                key.as_str().to_string(),
                value.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn serialize_optional_bytes<S>(value: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(bytes) => serializer.serialize_some(&encode_bytes(bytes)),
        None => serializer.serialize_none(),
    }
}

fn encode_bytes(data: &[u8]) -> Cow<str> {
    if let Ok(value) = std::str::from_utf8(data) {
        Cow::Borrowed(value)
    } else {
        Cow::Owned(STANDARD.encode(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::{HeaderName, HeaderValue, Method};
    use pretty_assertions::assert_eq;

    fn create_headers(list: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (key, value) in list {
            headers.insert(
                HeaderName::from_static(key),
                HeaderValue::from_static(value),
            );
        }
        headers
    }

    #[test]
    fn test_render_markdown() {
        let mut render = Recorder::new("http://example.com/", Method::GET.as_str());
        render
            .set_req_headers(&create_headers(&[("content-type", "plain/text")]))
            .set_req_body(Bytes::from("req_body"))
            .set_res_status(StatusCode::OK)
            .set_res_headers(&create_headers(&[(
                "content-type",
                "application/json; charset=utf-8",
            )]))
            .set_res_body(Bytes::from(r#"{"message":"OK"}"#))
            .add_error("error".to_string());
        let expect = r#"
# GET http://example.com/

REQUEST HEADERS
```
content-type: plain/text
```

REQUEST BODY
```
req_body
```

RESPONSE STATUS: 200

RESPONSE HEADERS
```
content-type: application/json; charset=utf-8
```

RESPONSE BODY
```json
{"message":"OK"}
```

ERROR: error"#;
        assert_eq!(expect, render.traffic.to_markdown());
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
