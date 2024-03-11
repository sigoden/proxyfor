use crate::traffic::{Body, Header, Headers, Traffic};

use http::{HeaderMap, StatusCode, Version};

#[derive(Debug)]
pub struct Recorder {
    traffic: Traffic,
    valid: bool,
    print_mode: PrintMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrintMode {
    PathOnly,
    Markdown,
}

impl Recorder {
    pub fn new(uri: &str, method: &str) -> Self {
        let traffic = Traffic::new(uri, method);
        Self {
            traffic,
            valid: true,
            print_mode: PrintMode::Markdown,
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

    pub fn change_print_mode(&mut self, print_mode: PrintMode) -> &mut Self {
        self.print_mode = print_mode;
        self
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn take_traffic(self) -> Traffic {
        self.traffic
    }

    pub fn print(&self) {
        match self.print_mode {
            PrintMode::PathOnly => {
                let (method, uri, _) = self.traffic.head();
                println!("# {method} {uri}");
            }
            PrintMode::Markdown => {
                println!("{}", self.traffic.to_markdown(true));
            }
        }
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

fn convert_headers(headers: &HeaderMap) -> Headers {
    headers
        .iter()
        .map(|(key, value)| Header::new(key.as_str(), value.to_str().unwrap_or_default()))
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
    fn test_recorder() {
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
        assert_eq!(recorder.traffic.to_markdown(true), expect);
    }
}
