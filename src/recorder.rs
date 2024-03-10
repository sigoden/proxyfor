use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http::{HeaderMap, StatusCode, Version};
use serde::Serialize;
use serde_json::{json, Value};

const HEX_VIEW_SIZE: usize = 320;

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

pub type Headers = Vec<Header>;

#[derive(Debug, Clone, Serialize)]
pub struct Header {
    name: String,
    value: String,
}

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
        println!("{}", self.traffic.to_markdown(true));
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

    pub fn to_markdown(&self, print: bool) -> String {
        let mut lines: Vec<String> = vec![];
        lines.push(format!("\n# {} {}", self.method, self.uri));

        if let Some(headers) = &self.req_headers {
            lines.push(render_header("REQUEST HEADERS", headers));
        }

        if let Some(body) = &self.req_body {
            lines.push(render_body("REQUEST BODY", body, &self.req_headers, print));
        }

        if let Some(status) = &self.status {
            lines.push(format!("RESPONSE STATUS: {status}"));
        }

        if let Some(headers) = &self.res_headers {
            lines.push(render_header("RESPONSE HEADERS", headers));
        }

        if let Some(body) = &self.res_body {
            lines.push(render_body("RESPONSE BODY", body, &self.res_headers, print));
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
            "markdown" => Ok((self.to_markdown(false), "text/markdown; charset=UTF-8")),
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

fn convert_headers(headers: &HeaderMap) -> Headers {
    headers
        .iter()
        .map(|(key, value)| Header {
            name: key.as_str().to_string(),
            value: value.to_str().unwrap_or_default().to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use http::{HeaderName, HeaderValue, Method};
    use pretty_assertions::assert_eq;

    fn create_recorder1() -> Recorder {
        let mut recorder = Recorder::new("http://example.com/?q1=3", Method::PUT.as_str());
        recorder
            .set_req_headers(&create_headers(&[
                ("content-type", "plain/text"),
                ("cookie", "c1=1; c2=2"),
                ("cookie", "c3=3"),
            ]))
            .set_req_body("req_body".as_bytes())
            .set_res_status(StatusCode::OK)
            .set_res_headers(&create_headers(&[
                ("content-type", "application/json; charset=utf-8"),
                (
                    "set-cookie",
                    "sc1=1; path=/; domain=example.com; expires=Wed, 21 Oct 2015 07:28:00 GMT",
                ),
                (
                    "set-cookie",
                    "sc2=2; path=/; domain=example.com; expires=Wed, 21 Oct 2015 07:28:00 GMT",
                ),
            ]))
            .set_res_body(r#"{"message":"OK"}"#.as_bytes())
            .add_error("error".to_string());
        recorder
    }

    fn create_headers(list: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (key, value) in list {
            headers.append(
                HeaderName::from_static(key),
                HeaderValue::from_static(value),
            );
        }
        headers
    }

    #[test]
    fn test_render_markdown() {
        let recorder = create_recorder1();
        let expect = r#"
# PUT http://example.com/?q1=3

REQUEST HEADERS
```
content-type: plain/text
cookie: c1=1; c2=2
cookie: c3=3
```

REQUEST BODY
```
req_body
```

RESPONSE STATUS: 200

RESPONSE HEADERS
```
content-type: application/json; charset=utf-8
set-cookie: sc1=1; path=/; domain=example.com; expires=Wed, 21 Oct 2015 07:28:00 GMT
set-cookie: sc2=2; path=/; domain=example.com; expires=Wed, 21 Oct 2015 07:28:00 GMT
```

RESPONSE BODY
```json
{"message":"OK"}
```

ERROR: error"#;
        assert_eq!(expect, recorder.traffic.to_markdown(false));
    }

    #[test]
    fn test_render_curl() {
        let recorder = create_recorder1();
        let expect = r#"curl http://example.com/?q1=3 \
  -X PUT \
  -H 'content-type: plain/text' \
  -H 'cookie: c1=1; c2=2' \
  -H 'cookie: c3=3' \
  -d 'req_body'"#;
        assert_eq!(expect, recorder.traffic.to_curl());
    }

    #[test]
    fn test_render_har() {
        let recorder = create_recorder1();
        let expect = r#"{
  "log": {
    "version": "1.2",
    "creator": {
      "name": "proxyfor",
      "version": "0.2.0",
      "comment": ""
    },
    "pages": [],
    "entries": [
      {
        "request": {
          "method": "PUT",
          "url": "http://example.com/?q1=3",
          "httpVersion": null,
          "cookies": [
            {
              "name": "c1",
              "value": "1"
            },
            {
              "name": "c2",
              "value": "2"
            },
            {
              "name": "c3",
              "value": "3"
            }
          ],
          "headers": [
            {
              "name": "content-type",
              "value": "plain/text"
            },
            {
              "name": "cookie",
              "value": "c1=1; c2=2"
            },
            {
              "name": "cookie",
              "value": "c3=3"
            }
          ],
          "queryString": [
            {
              "name": "q1",
              "value": "3"
            }
          ],
          "postData": {
            "mimeType": "plain/text",
            "text": "req_body"
          },
          "headersSize": -1,
          "bodySize": -1
        },
        "response": {
          "status": 200,
          "statusText": "",
          "httpVersion": null,
          "cookies": [
            {
              "name": "sc1",
              "value": "1",
              "path": "/",
              "domain": "example.com",
              "expries": "2015-10-21T07:28:00Z"
            },
            {
              "name": "sc2",
              "value": "2",
              "path": "/",
              "domain": "example.com",
              "expries": "2015-10-21T07:28:00Z"
            }
          ],
          "headers": [
            {
              "name": "content-type",
              "value": "application/json; charset=utf-8"
            },
            {
              "name": "set-cookie",
              "value": "sc1=1; path=/; domain=example.com; expires=Wed, 21 Oct 2015 07:28:00 GMT"
            },
            {
              "name": "set-cookie",
              "value": "sc2=2; path=/; domain=example.com; expires=Wed, 21 Oct 2015 07:28:00 GMT"
            }
          ],
          "content": {
            "mimeType": "application/json; charset=utf-8",
            "text": "{\"message\":\"OK\"}"
          },
          "redirectURL": "",
          "headersSize": -1,
          "bodySize": -1
        }
      }
    ]
  }
}"#;
        assert_eq!(
            expect,
            serde_json::to_string_pretty(&recorder.traffic.to_har()).unwrap()
        );
    }

    #[test]
    fn test_render_body() {
        let body = Body::new(&[
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
        assert_eq!(expect, output);
    }

    #[test]
    fn test_render_body_print() {
        let body = Body::new(&[
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
        assert_eq!(expect, output);
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
