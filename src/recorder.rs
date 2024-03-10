use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http::{HeaderMap, StatusCode, Version};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug)]
pub struct Recorder {
    traffic: Traffic,
    valid: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    uri: String,
    method: String,
    req_version: Option<String>,
    req_headers: Option<Headers>,
    req_body: Option<Body>,
    status: Option<u16>,
    res_headers: Option<Headers>,
    res_version: Option<String>,
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
            valid: true,
        }
    }

    pub fn set_req_version(&mut self, http_version: &Version) -> &mut Self {
        self.traffic.req_version = Some(format!("{http_version:?}"));
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

    pub fn set_res_version(&mut self, http_version: &Version) -> &mut Self {
        self.traffic.res_version = Some(format!("{http_version:?}"));
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

    pub fn check_match(&mut self, is_match: bool) -> &mut Self {
        self.valid = self.valid && is_match;
        self
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn take_traffic(self) -> Traffic {
        self.traffic
    }

    pub fn print(&self) {
        println!("{}", self.traffic.to_markdown());
    }
}

impl Traffic {
    pub fn new(uri: &str, method: &str) -> Self {
        Self {
            uri: uri.to_string(),
            method: method.to_string(),
            req_version: None,
            req_headers: None,
            req_body: None,
            status: None,
            res_version: None,
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

    pub fn to_har(&self) -> Value {
        let request = json!({
            "method": self.method,
            "url": self.uri,
            "httpVersion": self.req_version,
            "cookies": har_req_cookies(&self.req_headers),
            "headers": har_headers(&self.req_headers),
            "queryString": har_query_string(&self.uri),
            "postData": har_body(&self.req_body, &self.req_headers),
            "headersSize": -1,
            "bodySize": -1,
        });
        let response = match self.status {
            Some(status) => json!({
                "status": status,
                "statusText": "",
                "httpVersion": self.res_version,
                "cookies": har_res_cookies(&self.res_headers),
                "headers": har_headers(&self.res_headers),
                "content": har_body(&self.res_body, &self.res_headers),
                "redirectURL": get_header_value(&self.res_headers, "location").unwrap_or_default(),
                "headersSize": -1,
                "bodySize": -1,
            }),
            None => json!({}),
        };
        json!({
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "proxyfor",
                    "version": env!("CARGO_PKG_VERSION"),
                    "comment": "",
                },
                "pages": [],
                "entries": [
                    {
                        "request": request,
                        "response": response
                    }
                ]
            }
        })
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
            "har" => Ok((
                serde_json::to_string_pretty(&self.to_har())?,
                "application/json; charset=UTF-8",
            )),
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
        if self.recorder.is_valid() {
            self.recorder.print();
        }
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

fn har_headers(headers: &Option<Headers>) -> Value {
    match headers {
        Some(headers) => headers
            .iter()
            .map(|(key, value)| json!({ "name": key, "value": value }))
            .collect(),
        None => json!([]),
    }
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
            .iter()
            .filter(|(key, _)| key.as_str() == "cookie")
            .flat_map(|(_, value)| value.split(';').map(|v| v.trim()).collect::<Vec<&str>>())
            .filter_map(|value| {
                value
                    .split_once('=')
                    .map(|(k, v)| json!({ "name": k, "value": v }))
            })
            .collect(),
        None => json!([]),
    }
}

fn har_body(body: &Option<Body>, headers: &Option<Headers>) -> Value {
    let content_type = get_header_value(headers, "content-type").unwrap_or_default();
    match body {
        Some(body) => {
            let mut value = json!({"mimeType": content_type, "text": body.value});
            if !body.is_utf8() {
                value["encoding"] = "base64".into();
            }
            value
        }
        None => json!({"mimeType": content_type, "text":""}),
    }
}

fn har_res_cookies(headers: &Option<Headers>) -> Value {
    match headers {
        Some(headers) => headers
            .iter()
            .filter(|(key, _)| key.as_str() == "set-cookie")
            .filter_map(|(_, value)| {
                cookie::Cookie::parse(value).ok().map(|cookie| {
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
                            json_cookie["expries"] = datetime.into();
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
    headers
        .as_ref()
        .and_then(|v| v.get(key).map(|v| v.as_str()))
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
