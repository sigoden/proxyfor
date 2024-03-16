use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Serialize, Serializer};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::state::Head;

const HEX_VIEW_SIZE: usize = 320;

#[derive(Debug, Clone, Serialize)]
pub struct Traffic {
    pub uri: String,
    pub method: String,
    #[serde(serialize_with = "serialize_datetime")]
    pub start: OffsetDateTime,
    pub time: Option<usize>,
    pub req_version: Option<String>,
    pub req_headers: Option<Headers>,
    pub req_headers_size: Option<usize>,
    pub req_body: Option<Body>,
    pub req_body_size: Option<usize>,
    pub status: Option<u16>,
    pub res_version: Option<String>,
    pub res_headers: Option<Headers>,
    pub res_headers_size: Option<usize>,
    pub res_body: Option<Body>,
    pub res_body_size: Option<usize>,
    pub res_body_decompress_size: Option<usize>,
    pub websocket_id: Option<usize>,
    pub error: Option<String>,
}

impl Traffic {
    pub fn new(uri: &str, method: &str) -> Self {
        Self {
            uri: uri.to_string(),
            method: method.to_string(),
            start: OffsetDateTime::now_utc(),
            time: None,
            req_version: None,
            req_headers: None,
            req_headers_size: None,
            req_body: None,
            req_body_size: None,
            status: None,
            res_version: None,
            res_headers: None,
            res_headers_size: None,
            res_body: None,
            res_body_size: None,
            res_body_decompress_size: None,
            websocket_id: None,
            error: None,
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

    pub fn markdown(&self, print: bool) -> String {
        let mut lines: Vec<String> = vec![];
        lines.push(format!("\n# {}", self.oneline()));

        if let Some(headers) = &self.req_headers {
            lines.push(render_header("REQUEST HEADERS", headers));
        }

        if let Some(body) = &self.req_body {
            if !body.value.is_empty() {
                lines.push(render_body("REQUEST BODY", body, &self.req_headers, print));
            }
        }

        if let Some(headers) = &self.res_headers {
            lines.push(render_header("RESPONSE HEADERS", headers));
        }

        if let Some(body) = &self.res_body {
            if !body.value.is_empty() {
                lines.push(render_body("RESPONSE BODY", body, &self.res_headers, print));
            }
        }

        if let Some(error) = &self.error {
            lines.push(render_error(error));
        }
        lines.join("\n\n")
    }

    pub fn har(&self) -> Value {
        let entries = match self.har_entry() {
            Some(v) => vec![v],
            None => vec![],
        };
        wrap_entries(entries)
    }

    pub fn har_entry(&self) -> Option<Value> {
        self.status?;
        let request = json!({
            "method": self.method,
            "url": self.uri,
            "httpVersion": self.req_version,
            "cookies": har_req_cookies(&self.req_headers),
            "headers": har_headers(&self.req_headers),
            "queryString": har_query_string(&self.uri),
            "postData": har_req_body(&self.req_body, &self.req_headers),
            "headersSize": har_size(&self.req_headers_size),
            "bodySize": har_size(&self.req_body_size),
        });
        let response = json!({
            "status": self.status.unwrap_or_default(),
            "statusText": "",
            "httpVersion": self.res_version,
            "cookies": har_res_cookies(&self.res_headers),
            "headers": har_headers(&self.res_headers),
            "content": har_res_body(&self.res_body, &self.res_headers, &self.res_body_size, &self.res_body_decompress_size),
            "redirectURL": get_header_value(&self.res_headers, "location").unwrap_or_default(),
            "headersSize": har_size(&self.res_headers_size),
            "bodySize": har_size(&self.res_body_size),
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

    pub fn curl(&self) -> String {
        let mut output = format!("curl {}", self.uri);
        let escape_single_quote = |v: &str| v.replace('\'', r#"'\''"#);
        if self.method != "GET" {
            output.push_str(&format!(" \\\n  -X {}", self.method));
        }
        for header in self.req_headers.iter().flatten() {
            if header.name != "content-length" {
                output.push_str(&format!(
                    " \\\n  -H '{}: {}'",
                    header.name,
                    escape_single_quote(&header.value)
                ))
            }
        }
        if let Some(body) = &self.req_body {
            if !body.value.is_empty() {
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

    pub fn export(&self, format: &str) -> Result<(String, &'static str)> {
        match format {
            "markdown" => Ok((self.markdown(false), "text/markdown; charset=UTF-8")),
            "har" => Ok((
                serde_json::to_string_pretty(&self.har())?,
                "application/json; charset=UTF-8",
            )),
            "curl" => Ok((self.curl(), "text/plain; charset=UTF-8")),
            "" => Ok((
                serde_json::to_string_pretty(&self)?,
                "application/json; charset=UTF-8",
            )),
            _ => bail!("Unsupported format: {}", format),
        }
    }

    pub(crate) fn head(&self, id: usize) -> Head {
        Head {
            id,
            method: self.method.clone(),
            uri: self.uri.clone(),
            status: self.status,
            time: self.time,
            size: self.res_body_size,
            mime: extract_content_type(&self.res_headers).map(|v| v.to_string()),
        }
    }
}

pub type Headers = Vec<Header>;

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
}

impl Body {
    pub fn bytes(bytes: &[u8]) -> Self {
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

    pub fn text(value: &str) -> Self {
        Body {
            encode: "utf8".to_string(),
            value: value.to_string(),
        }
    }

    pub fn is_utf8(&self) -> bool {
        self.encode == "utf8"
    }
}

fn render_header(title: &str, headers: &Headers) -> String {
    let value = headers
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
        Some(headers) => headers.iter().map(|header| json!(header)).collect(),
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

fn har_res_body(
    body: &Option<Body>,
    headers: &Option<Headers>,
    body_size: &Option<usize>,
    decompress_size: &Option<usize>,
) -> Value {
    let content_type = get_header_value(headers, "content-type").unwrap_or_default();
    match body {
        Some(body) => {
            let mut value =
                json!({"size": har_size(body_size), "mimeType": content_type, "text": body.value});
            if !body.is_utf8() {
                value["encoding"] = "base64".into();
            }
            if let (Some(body_size), Some(decompress_size)) = (body_size, decompress_size) {
                value["compression"] = (*decompress_size as isize - *body_size as isize).into();
            }
            value
        }
        None => json!({"size": 0, "mimeType": content_type, "text": ""}),
    }
}

fn har_res_cookies(headers: &Option<Headers>) -> Value {
    match headers {
        Some(headers) => headers
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
        v.iter()
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn test_render_body() {
        let body = Body::bytes(&[
            0x6b, 0x4e, 0x1a, 0xc3, 0xaf, 0x03, 0xd2, 0x1e, 0x7e, 0x73, 0xba, 0xc8, 0xbd, 0x84,
            0x0f, 0x83,
        ]);
        let output = render_body(
            "REQUEST BODY",
            &body,
            &Some(vec![Header {
                name: "content-type".into(),
                value: "application/octet-stream".into(),
            }]),
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
        let body = Body::bytes(&[
            0x6b, 0x4e, 0x1a, 0xc3, 0xaf, 0x03, 0xd2, 0x1e, 0x7e, 0x73, 0xba, 0xc8, 0xbd, 0x84,
            0x0f, 0x83,
        ]);
        let output = render_body(
            "REQUEST BODY",
            &body,
            &Some(vec![Header {
                name: "content-type".into(),
                value: "plain/text".into(),
            }]),
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
