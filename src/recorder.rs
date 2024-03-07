use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};

const HEX_VIEW_SIZE: usize = 320;

#[derive(Debug)]
pub(crate) struct Recorder {
    path: String,
    method: Method,
    req_headers: Option<HeaderMap>,
    req_body: Option<Bytes>,
    res_status: Option<StatusCode>,
    res_headers: Option<HeaderMap>,
    res_body: Option<Bytes>,
    error: Option<String>,
}

impl Recorder {
    pub fn new(path: String, method: Method) -> Self {
        Self {
            path,
            method,
            req_headers: None,
            req_body: None,
            res_status: None,
            res_headers: None,
            res_body: None,
            error: None,
        }
    }

    // Remove the unused functions
    pub fn set_req_headers(mut self, headers: HeaderMap) -> Self {
        self.req_headers = Some(headers);
        self
    }

    pub fn set_req_body(mut self, body: Bytes) -> Self {
        if body.is_empty() {
            self
        } else {
            self.req_body = Some(body);
            self
        }
    }

    pub fn set_res_status(mut self, status: StatusCode) -> Self {
        self.res_status = Some(status);
        self
    }

    pub fn set_res_headers(mut self, headers: HeaderMap) -> Self {
        self.res_headers = Some(headers);
        self
    }

    pub fn set_res_body(mut self, body: Bytes) -> Self {
        if body.is_empty() {
            self
        } else {
            self.res_body = Some(body);
            self
        }
    }

    pub fn set_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self
    }

    pub fn render(&self) -> String {
        let mut lines: Vec<String> = vec![];
        lines.push(format!("\n# {} {}", self.method, self.path));

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

    pub fn print(&self) {
        println!("{}", self.render());
    }
}

fn render_header(title: &str, headers: &HeaderMap) -> String {
    let value = headers
        .iter()
        .map(|(key, value)| format!("{key}: {}", value.to_str().unwrap_or_default()))
        .collect::<Vec<String>>()
        .join("\n");
    format!(
        r#"{title}
```
{value}
```"#
    )
}

fn render_body(title: &str, body: &Bytes, headers: &Option<HeaderMap>) -> String {
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

fn recognize_lang(is_utf8: bool, headers: &Option<HeaderMap>) -> &str {
    if !is_utf8 {
        return "";
    }
    headers
        .as_ref()
        .and_then(|v| v.get("content-type"))
        .and_then(|v| v.to_str().ok())
        .map(md_lang)
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

#[cfg(test)]
mod tests {
    use super::*;

    use http::{header::CONTENT_TYPE, HeaderValue};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_render() {
        let mut req_readers = HeaderMap::new();
        req_readers.insert(CONTENT_TYPE, HeaderValue::from_static("plain/text"));
        let mut res_headers = HeaderMap::new();
        res_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let render = Recorder::new("http://example.com/".to_string(), Method::GET)
            .set_req_headers(req_readers)
            .set_req_body(Bytes::from("req_body"))
            .set_res_status(StatusCode::OK)
            .set_res_headers(res_headers)
            .set_res_body(Bytes::from(r#"{"message":"OK"}"#))
            .set_error("error".to_string());
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

RESPONSE STATUS: 200 OK

RESPONSE HEADERS
```
content-type: application/json
```

RESPONSE BODY
```json
{"message":"OK"}
```

ERROR: error"#;
        assert_eq!(expect, render.render());
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
