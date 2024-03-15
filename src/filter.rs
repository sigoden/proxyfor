use anyhow::{Context, Result};
use fancy_regex::Regex;

pub fn parse_title_filters(filters: &[String]) -> Result<Vec<TitleFilter>> {
    let mut output = vec![];
    for filter in filters {
        if let Some(re) = filter.strip_prefix('/').and_then(|v| v.strip_suffix('/')) {
            let regex = Regex::new(&re.to_lowercase())
                .with_context(|| format!("Invalid filter regex: {filter}"))?;
            output.push(TitleFilter::Regex(regex));
        } else {
            output.push(TitleFilter::Plain(filter.to_lowercase()));
        }
    }
    Ok(output)
}

pub fn is_match_title(filters: &[TitleFilter], title: &str) -> bool {
    if filters.is_empty() {
        true
    } else {
        let title = title.to_lowercase();
        filters.iter().any(|v| v.is_match(&title))
    }
}

pub fn is_match_type(filters: &[String], content_type: &str) -> bool {
    if filters.is_empty() {
        true
    } else {
        let content_type = content_type.to_lowercase();
        filters.iter().any(|v| content_type.starts_with(v))
    }
}

#[derive(Debug)]
pub enum TitleFilter {
    Regex(Regex),
    Plain(String),
}

impl TitleFilter {
    pub fn is_match(&self, value: &str) -> bool {
        match self {
            TitleFilter::Regex(v) => v.is_match(value).unwrap_or_default(),
            TitleFilter::Plain(v) => value.contains(v),
        }
    }
}

#[test]
fn test_filters() {
    let filters = parse_title_filters(&[
        "postman-echo.com".to_string(),
        "/^(GET|POST) https:\\/\\/httpbin.org/".to_string(),
    ])
    .unwrap();
    assert!(is_match_title(&filters, "GET https://postman-echo.com/get"));
    assert!(is_match_title(&filters, "GET https://httpbin.org"));
    assert!(is_match_title(&filters, "POST https://httpbin.org"));
    assert!(!is_match_title(&filters, "PUT https://httpbin.org"));
}

#[test]
fn test_is_asset() {
    let filters = vec!["application/json".to_string()];
    assert!(is_match_type(&filters, "application/json"));
    let filters = vec!["application/".to_string()];
    assert!(is_match_type(&filters, "application/json"));
}
