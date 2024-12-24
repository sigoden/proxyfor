# Proxyfor

[![CI](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/proxyfor.svg)](https://crates.io/crates/proxyfor)
[![Docker Pulls](https://img.shields.io/docker/pulls/sigoden/proxyfor)](https://hub.docker.com/r/sigoden/proxyfor)

A powerful and flexible proxy CLI for capturing and inspecting HTTP(S) and WS(S) traffic.

## Key Features

*   **Forward & Reverse Proxy:** Supports both forward proxy (client explicitly uses the proxy) and reverse proxy (proxy sits in front of the server).
*   **Multi-Protocol Support:** Handles HTTP, HTTPS, WebSocket (WS), and secure WebSocket (WSS) protocols.
*   **Flexible Filtering:** Filter traffic based on method, URI, and content-type for targeted analysis.
*   **Multiple Interfaces:** Includes a user-friendly Terminal User Interface (TUI) and a web-based interface (WebUI) for inspecting captured data.
*   **CA Certificate Management:** Simplifies the process of installing the necessary CA certificates to decrypt HTTPS traffic.
*   **Export Options:** Export captured traffic in various formats, including Markdown, cURL commands, and HAR files.
*   **Non-Blocking Streaming:** Captures request/response data in a non-blocking, streaming fashion for efficient handling of large volumes of traffic.
*   **Cross-Platform & Standalone:** Delivered as a single, self-contained executable for Windows, macOS, and Linux, simplifying setup and distribution.

## Screenshots

**Terminal User Interface (TUI)**
![proxyfor-tui](https://github.com/user-attachments/assets/87a93e09-4783-4273-85b6-002762909fc3)

**Web User Interface (WebUI)**
![proxyfor-webui](https://github.com/user-attachments/assets/4f1f921a-95ec-44e0-8a2f-671614c0b934)

## Installation

### With cargo

```
cargo install proxyfor
```

### With docker

```
docker run -v ~/.proxyfor:/.proxyfor -p 8080:8080 --rm sigoden/proxyfor --web 
```

### Binaries on macOS, Linux, Windows

Download from [Github Releases](https://github.com/sigoden/proxyfor/releases), unzip and add proxyfor to your $PATH.

## Proxy Modes Explained

### Forward Proxy

In this mode, your client applications (e.g., web browsers, curl) are configured to send their requests to `proxyfor`, which then forwards them to the target servers. You would configure your client to use a proxy at `http://127.0.0.1:8080`.

```bash
proxyfor
curl -x http://127.0.0.1:8080 httpbin.org/ip
```

### Reverse Proxy

In reverse proxy mode, `proxyfor` sits in front of a target server. Clients access `proxyfor` and it forwards the requests to the defined URL. This mode is ideal when clients cannot be configured to use a proxy.

```bash
proxyfor https://httpbin.org
curl http://127.0.0.1:8080/ip
```

## Command Line Interface (CLI)

```
Usage: proxyfor [OPTIONS] [URL]

Arguments:
  [URL]  Reverse proxy url

Options:
  -l, --listen <ADDR>         Listening ip and port address [default: 0.0.0.0:8080]
  -f, --filters <REGEX>       Only inspect http(s) traffic whose `{method} {uri}` matches the regex
  -m, --mime-filters <VALUE>  Only inspect http(s) traffic whose content-type matches the value
  -W, --web                   Enable user-friendly web interface
  -T, --tui                   Eenter TUI
  -D, --dump                  Dump all traffics
  -h, --help                  Print help
  -V, --version               Print version
```

### Choosing User Interface

`proxyfor` provides several ways to interact with captured traffic:

```sh
proxyfor                   # Enter TUI, equal to `proxyfor --tui`
proxyfor --web             # Serve WebUI
proxyfor --web --tui       # Serve WebUI + Enter TUI
proxyfor --dump            # Dump all traffics to console
proxyfor > proxyfor.md     # Dump all traffics to markdown file
```

### Specifying Address and Port

Customize the listening address and port:

```sh
proxyfor -l 8081
proxyfor -l 127.0.0.1
proxyfor -l 127.0.0.1:8081
```

### Filtering Traffic

Apply regex filters to limit captured traffic based on method and URI:

```sh
proxyfor -f httpbin.org/ip -f httpbin.org/anything
proxyfor -f '/^(get|post) https:\/\/httpbin.org/'
```

Filter based on MIME types:

```sh
proxyfor -m application/json -m application/ld+json
proxyfor -m text/
```

## CA Certificate Installation

To decrypt HTTPS traffic, you must install `proxyfor`'s CA certificate on your device. The easiest way to do this is to use the built-in certificate installation app.

1. Start `proxyfor` with desired proxy settings.
2. On your target device, configure the device to use `proxyfor` as the proxy.
3. Open a web browser on the target device and navigate to [proxyfor.local](http://proxyfor.local).
4. Follow the on-screen instructions to download and install the CA certificate.

![proxyfor.local](https://github.com/sigoden/proxyfor/assets/4012553/a5276872-8ab1-4794-9e97-ac7038ca5e4a)

## License

Copyright (c) 2024-∞ proxyfor-developers.

Proxyfor is made available under the terms of either the MIT License or the Apache License 2.0, at your option.

See the LICENSE-APACHE and LICENSE-MIT files for license details.