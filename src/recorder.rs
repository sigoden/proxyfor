use crate::{
    server::PrintMode,
    traffic::{Body, Header, Headers, Traffic},
};

use http::{HeaderMap, StatusCode, Version};
use std::time::Duration;

#[derive(Debug)]
pub(crate) struct Recorder {
    traffic: Traffic,
    valid: bool,
    print_mode: PrintMode,
}

impl Recorder {
    pub(crate) fn new(uri: &str, method: &str, print_mode: PrintMode) -> Self {
        let traffic = Traffic::new(uri, method);
        Self {
            traffic,
            valid: true,
            print_mode,
        }
    }

    pub(crate) fn set_req_version(&mut self, http_version: &Version) -> &mut Self {
        self.traffic.req_version = Some(format!("{http_version:?}"));
        self
    }

    pub(crate) fn set_req_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.traffic.req_headers = Some(map_headers(headers));
        self.traffic.req_headers_size = Some(cal_headers_size(headers));
        self
    }

    pub(crate) fn set_req_body(&mut self, body: &[u8]) -> &mut Self {
        self.traffic.req_body = Some(Body::bytes(body));
        self.traffic.req_body_size = Some(body.len());
        self
    }

    pub(crate) fn set_res_status(&mut self, status: StatusCode) -> &mut Self {
        self.traffic.status = Some(status.into());
        self
    }

    pub(crate) fn set_res_version(&mut self, http_version: &Version) -> &mut Self {
        self.traffic.res_version = Some(format!("{http_version:?}"));
        self
    }

    pub(crate) fn set_res_headers(&mut self, headers: &HeaderMap) -> &mut Self {
        self.traffic.res_headers = Some(map_headers(headers));
        self.traffic.res_headers_size = Some(cal_headers_size(headers));
        self
    }

    pub(crate) fn set_res_body(&mut self, body: &[u8], size: usize) -> &mut Self {
        self.traffic.res_body = Some(Body::bytes(body));
        self.traffic.res_body_size = Some(size);
        self.traffic.res_body_decompress_size = Some(body.len());
        self
    }

    pub(crate) fn set_websocket_id(&mut self, id: usize) -> &mut Self {
        self.traffic.websocket_id = Some(id);
        self
    }

    pub(crate) fn set_time(&mut self, time: Duration) -> &mut Self {
        self.traffic.time = Some(time.as_millis() as usize);
        self
    }

    pub(crate) fn add_error(&mut self, error: String) -> &mut Self {
        self.traffic.add_error(error);
        self
    }

    pub(crate) fn check_match(&mut self, is_match: bool) -> &mut Self {
        self.valid = self.valid && is_match;
        self
    }

    pub(crate) fn is_valid(&self) -> bool {
        self.valid
    }

    pub(crate) fn take_traffic(self) -> Traffic {
        self.traffic
    }

    pub(crate) fn print(&self) {
        match self.print_mode {
            PrintMode::Nothing => {}
            PrintMode::Oneline => {
                println!("# {}", self.traffic.oneline());
            }
            PrintMode::Markdown => {
                println!("{}", self.traffic.markdown(true));
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct ErrorRecorder {
    recorder: Recorder,
}

impl ErrorRecorder {
    pub(crate) fn new(recorder: Recorder) -> Self {
        Self { recorder }
    }

    pub(crate) fn add_error(&mut self, error: String) -> &mut Self {
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

fn map_headers(headers: &HeaderMap) -> Headers {
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

    use http::{HeaderName, HeaderValue, Method};
    use pretty_assertions::assert_eq;

    fn create_recorder1() -> Recorder {
        let mut recorder = Recorder::new(
            "http://example.com/?q1=3",
            Method::PUT.as_str(),
            PrintMode::Markdown,
        );
        let res_body = r#"{"message":"OK"}"#.as_bytes();
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
            .set_res_body(res_body, res_body.len())
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
# PUT http://example.com/?q1=3 200

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
        assert_eq!(recorder.traffic.markdown(true), expect);
    }
}
