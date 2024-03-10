use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http::{HeaderMap, StatusCode, Version};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::json;

#[derive(Debug)]
pub struct Recorder {
    traffic: Traffic,
    should_dump: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    uri: String,
    method: String,
    http_version: Option<String>,
    req_headers: Option<Headers>,
    req_body: Option<Body>,
    status: Option<u16>,
    res_headers: Option<Headers>,
    res_body: Option<Body>,
    error: Option<String>,
}

pub type Headers = IndexMap<String, String>;

#[derive(Debug, Clone, Serialize)]
pub struct Body {
    encode: String,
    value: String,
}

impl Recorder {
    pub fn new(uri: &str, method: &str) -> Self {
        let traffic = Traffic::new(uri, method);
        Self {
            traffic,
            should_dump: true,
        }
    }

    pub fn set_http_version(&mut self, http_version: &Version) -> &mut Self {
        self.traffic.http_version = Some(format!("{http_version:?}"));
        self
    }

    pub fn set_req_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.traffic.req_headers = Some(convert_headers(headers));
        self
    }

    pub fn set_req_body(&mut self, body: &[u8]) -> &mut Self {
        if body.is_empty() {
            self
        } else {
            self.traffic.req_body = Some(Body::new(body));
            self
        }
    }

    pub fn set_res_status(&mut self, status: StatusCode) -> &mut Self {
        self.traffic.status = Some(status.into());
        self
    }

    pub fn set_res_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.traffic.res_headers = Some(convert_headers(headers));
        self
    }

    pub fn set_res_body(&mut self, body: &[u8]) -> &mut Self {
        if body.is_empty() {
            self
        } else {
            self.traffic.res_body = Some(Body::new(body));
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
            http_version: None,
            req_headers: None,
            req_body: None,
            status: None,
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

    pub fn head(&self) -> (&str, &str, Option<u16>) {
        (&self.method, &self.uri, self.status)
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

        if let Some(status) = &self.status {
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

    pub fn to_har(&self) -> String {
        // har_cookies
        // har_qs
        // har_body
        let value = json!({
            "version": "1.2",
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": self.method,
                            "url": self.uri,
                            "httpVersion": self.http_version,
                            "headers": har_headers(&self.req_headers),
                        },
                        "response": {

                        }
                    }
                ]
            }
        });
        value.to_string()
    }

    pub fn to_curl(&self) -> String {
        let mut output = format!("curl {}", self.uri);
        let escape_single_quote = |v: &str| v.replace('\'', r#"'\''"#);
        if self.method != "GET" {
            output.push_str(&format!(" \\\n  -X {}", self.method));
        }
        for (key, value) in self.req_headers.iter().flatten() {
            if key != "content-length" {
                output.push_str(&format!(
                    " \\\n  -H '{}: {}'",
                    key,
                    escape_single_quote(value)
                ))
            }
        }
        if let Some(body) = &self.req_body {
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

    pub fn export<'a>(&'a self, format: &str) -> Result<(String, &'a str)> {
        match format {
            "markdown" => Ok((self.to_markdown(), "text/markdown; charset=UTF-8")),
            "har" => Ok((self.to_har(), "application/json; charset=UTF-8")),
            "curl" => Ok((self.to_curl(), "text/plain; charset=UTF-8")),
            _ => bail!("unsupported format: {}", format),
        }
    }
}

impl Body {
    pub fn new(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(value) => Body {
                encode: "utf8".to_string(),
                value: value.to_string(),
            },
            Err(_) => Body {
                encode: "base64".to_string(),
                value: STANDARD.encode(bytes),
            },
        }
    }

    pub fn is_utf8(&self) -> bool {
        self.encode == "utf8"
    }
}

#[derive(Debug)]
pub(crate) struct ErrorRecorder {
    recorder: Recorder,
}

impl ErrorRecorder {
    pub fn new(recorder: Recorder) -> Self {
        Self { recorder }
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

fn render_body(title: &str, body: &Body, headers: &Option<Headers>) -> String {
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

fn har_headers(headers: &Option<Headers>) -> serde_json::Value {
    match headers {
        Some(headers) => headers
            .iter()
            .map(|(key, value)| json!({ "name": key, "value": value }))
            .collect(),
        None => json!([]),
    }
}

fn extract_content_type(headers: &Option<Headers>) -> Option<&str> {
    headers
        .as_ref()
        .and_then(|v| v.get("content-type"))
        .map(|v| match v.split_once(';') {
            Some((v, _)) => v.trim(),
            None => v.as_str(),
        })
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
        let mut render = Recorder::new("http://example.com/", Method::PUT.as_str());
        render
            .set_req_headers(&create_headers(&[("content-type", "plain/text")]))
            .set_req_body("req_body".as_bytes())
            .set_res_status(StatusCode::OK)
            .set_res_headers(&create_headers(&[(
                "content-type",
                "application/json; charset=utf-8",
            )]))
            .set_res_body(r#"{"message":"OK"}"#.as_bytes())
            .add_error("error".to_string());
        let expect = r#"
# PUT http://example.com/

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
    fn test_render_curl() {
        let mut render = Recorder::new("http://example.com/", Method::PUT.as_str());
        render
            .set_req_headers(&create_headers(&[("content-type", "plain/text")]))
            .set_req_body("req_body".as_bytes());

        let expect = r#"curl http://example.com/ \
  -X PUT \
  -H 'content-type: plain/text' \
  -d 'req_body'"#;
        assert_eq!(expect, render.traffic.to_curl());
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
