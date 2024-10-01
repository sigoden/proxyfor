use anyhow::Result;
use async_compression::tokio::bufread::{BrotliDecoder, DeflateDecoder, GzipDecoder, ZstdDecoder};
use serde::Serializer;
use std::sync::{Arc, LazyLock};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::{
    fs::{self, File, OpenOptions},
    io::{AsyncRead, AsyncReadExt, BufReader, BufWriter},
};
use unicode_width::UnicodeWidthStr;

pub const ENC_EXT: &str = ".enc";

static CLIPBOARD: LazyLock<Arc<std::sync::Mutex<Option<arboard::Clipboard>>>> =
    LazyLock::new(|| std::sync::Arc::new(std::sync::Mutex::new(arboard::Clipboard::new().ok())));

pub fn ellipsis_tail(text: &str, width: u16) -> String {
    let width = width as _;
    let text_width = text.width();
    if text_width > width {
        format!("{}…", &text[..width - 1])
    } else {
        text.to_string()
    }
}

pub fn ellipsis_head(text: &str, width: u16) -> String {
    let width = width as _;
    let text_width = text.width();
    if text_width > width {
        format!("…{}", &text[text_width - width + 1..])
    } else {
        text.to_string()
    }
}

pub fn format_size(bytes: Option<u64>) -> String {
    match bytes {
        None => String::new(),
        Some(0) => "0".to_string(),
        Some(bytes) => {
            let prefix = ["b", "kb", "mb", "gb", "tb"];
            let mut i = 0;
            while i < prefix.len() && 1024u64.pow(i as u32 + 1) <= bytes {
                i += 1;
            }
            let precision = if bytes % 1024u64.pow(i as u32) == 0 {
                0
            } else {
                1
            };
            format!(
                "{:.prec$}{}",
                bytes as f64 / 1024f64.powi(i as i32),
                prefix[i],
                prec = precision
            )
        }
    }
}

pub fn format_time_delta(delta: Option<u64>) -> String {
    let mut delta = match delta {
        Some(ms) => ms,
        None => return String::from(""),
    };

    if delta == 0 {
        return String::from("0");
    }

    if delta > 1000 && delta < 10000 {
        let seconds = delta as f64 / 1000.0;
        return format!("{:.2}s", seconds);
    }

    let prefix = ["ms", "s", "min", "h"];
    let div = [1000, 60, 60];
    let mut i = 0;

    while i < div.len() && delta >= div[i] {
        delta /= div[i];
        i += 1;
    }

    format!("{}{}", delta, prefix[i])
}

pub fn next_idx(len: usize, idx: usize) -> usize {
    if idx >= len - 1 {
        0
    } else {
        idx + 1
    }
}

pub fn prev_idx(len: usize, idx: usize) -> usize {
    if idx == 0 {
        len - 1
    } else {
        idx - 1
    }
}

#[cfg(not(any(target_os = "android", target_os = "emscripten")))]
pub fn set_text(text: &str) -> anyhow::Result<()> {
    let mut clipboard = CLIPBOARD.lock().unwrap();
    match clipboard.as_mut() {
        Some(clipboard) => clipboard.set_text(text)?,
        None => anyhow::bail!("No available clipboard"),
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "emscripten"))]
pub fn set_text(_text: &str) -> anyhow::Result<()> {
    anyhow::bail!("No available clipboard")
}

pub async fn uncompress_data(encoding: &str, path: &str) -> Result<Vec<u8>> {
    let file = File::open(path).await?;
    let reader = BufReader::new(file);
    let mut decompressed = Vec::new();
    let mut decoder: Box<dyn AsyncRead + Unpin + Send> = match encoding {
        "deflate" => Box::new(DeflateDecoder::new(reader)),
        "gzip" => Box::new(GzipDecoder::new(reader)),
        "br" => Box::new(BrotliDecoder::new(reader)),
        "zstd" => Box::new(ZstdDecoder::new(reader)),
        _ => Box::new(reader),
    };
    decoder.read_to_end(&mut decompressed).await?;
    Ok(decompressed)
}

pub async fn uncompress_file(encoding: &str, source_path: &str, target_path: &str) -> Result<()> {
    let source_file = File::open(source_path).await?;
    let target_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(target_path)
        .await?;

    let reader = BufReader::new(source_file);
    let mut decoder: Box<dyn AsyncRead + Unpin + Send> = match encoding {
        "deflate" => Box::new(DeflateDecoder::new(reader)),
        "gzip" => Box::new(GzipDecoder::new(reader)),
        "br" => Box::new(BrotliDecoder::new(reader)),
        "zstd" => Box::new(ZstdDecoder::new(reader)),
        _ => Box::new(reader),
    };
    let mut writer = BufWriter::new(target_file);

    tokio::io::copy(&mut decoder, &mut writer).await?;
    fs::remove_file(source_path).await?;

    Ok(())
}

// see https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
pub fn to_ext_name(mime: &str) -> &str {
    match mime {
        "audio/aac" => ".aac",
        "application/x-abiword" => ".abw",
        "image/apng" => ".apng",
        "application/x-freearc" => ".arc",
        "image/avif" => ".avif",
        "video/x-msvideo" => ".avi",
        "application/vnd.amazon.ebook" => ".azw",
        "application/octet-stream" => ".bin",
        "image/bmp" => ".bmp",
        "application/x-bzip" => ".bz",
        "application/x-bzip2" => ".bz2",
        "application/x-cdf" => ".cda",
        "application/x-csh" => ".csh",
        "text/css" => ".css",
        "text/csv" => ".csv",
        "application/msword" => ".doc",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => ".docx",
        "application/vnd.ms-fontobject" => ".eot",
        "application/epub+zip" => ".epub",
        "application/gzip" | "application/x-gzip" => ".gz",
        "image/gif" => ".gif",
        "text/html" | "text/htm" => ".html",
        "image/vnd.microsoft.icon" => ".ico",
        "text/calendar" => ".ics",
        "application/java-archive" => ".jar",
        "image/jpeg" => ".jpeg",
        "text/javascript" => ".js",
        "application/json" => ".json",
        "application/ld+json" => ".jsonld",
        "audio/midi" | "audio/x-midi" => ".mid",
        "audio/mpeg" => ".mp3",
        "video/mp4" => ".mp4",
        "video/mpeg" => ".mpeg",
        "application/vnd.apple.installer+xml" => ".mpkg",
        "application/vnd.oasis.opendocument.presentation" => ".odp",
        "application/vnd.oasis.opendocument.spreadsheet" => ".ods",
        "application/vnd.oasis.opendocument.text" => ".odt",
        "audio/ogg" => ".oga",
        "video/ogg" => ".ogv",
        "application/ogg" => ".ogx",
        "font/otf" => ".otf",
        "image/png" => ".png",
        "application/pdf" => ".pdf",
        "application/x-httpd-php" => ".php",
        "application/vnd.ms-powerpoint" => ".ppt",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => ".pptx",
        "application/vnd.rar" => ".rar",
        "application/rtf" => ".rtf",
        "application/x-sh" => ".sh",
        "image/svg+xml" => ".svg",
        "application/x-tar" => ".tar",
        "image/tiff" => ".tif",
        "video/mp2t" => ".ts",
        "font/ttf" => ".ttf",
        "text/plain" => ".txt",
        "application/vnd.visio" => ".vsd",
        "audio/wav" => ".wav",
        "audio/webm" => ".weba",
        "video/webm" => ".webm",
        "image/webp" => ".webp",
        "font/woff" => ".woff",
        "font/woff2" => ".woff2",
        "application/xhtml+xml" => ".xhtml",
        "application/vnd.ms-excel" => ".xls",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => ".xlsx",
        "application/xml" | "text/xml" => ".xml",
        "application/vnd.mozilla.xul+xml" => ".xul",
        "application/zip" | "x-zip-compressed" => ".zip",
        "video/3gpp" | "audio/3gpp" => ".3gp",
        "video/3gpp2" | "audio/3gpp2" => ".3g2",
        "application/x-7z-compressed" => ".7z",
        _ => {
            if mime.starts_with("text/") {
                ".txt"
            } else {
                ""
            }
        }
    }
}

pub fn to_md_lang(mime: &str) -> &str {
    if let Some(value) = mime
        .strip_prefix("text/")
        .or_else(|| mime.strip_prefix("application/"))
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

pub fn serialize_datetime<S>(date: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let formatted = date.format(&Rfc3339).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&formatted)
}

pub fn serialize_option_datetime<S>(
    date: &Option<OffsetDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match date {
        Some(date) => serialize_datetime(date, serializer),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md_lang() {
        assert_eq!(to_md_lang("application/json"), "json");
        assert_eq!(to_md_lang("application/xml"), "xml");
        assert_eq!(to_md_lang("application/octet-stream"), "octet-stream");
        assert_eq!(to_md_lang("application/javascript"), "javascript");
        assert_eq!(to_md_lang("text/x-rust"), "rust");
        assert_eq!(to_md_lang("text/css"), "css");
    }
}
