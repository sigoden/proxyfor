# Proxyfor

[![CI](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/proxyfor.svg)](https://crates.io/crates/proxyfor)
[![Docker Pulls](https://img.shields.io/docker/pulls/sigoden/proxyfor)](https://hub.docker.com/r/sigoden/proxyfor)

A lightweight proxy for capturing HTTP(S) and WS(S) traffic.

## Features

- Support forward/reverse proxy
- Support filtering
- Support HTTP/HTTPS/WS/WSS protocols
- Integrate terminal user interface (TUI)
- Integrate web user interface (WebUI)
- Integrate certificates installation webapp
- Capture req/res bodies in a non-blocking, streaming manner
- Export in Markdown, cURL, or HAR formats
- Written in Rust, offering a single executable with no external dependencies

## Screenshots

**Terminal User Inferace**
![proxyfor-tui](https://github.com/user-attachments/assets/01db8ada-0b0c-4ddc-bc3f-045cfdb67d64)

**Web User Inferace**
![proxyfor-webui](https://github.com/user-attachments/assets/b13ffe34-69e5-4513-b904-243c391528b2)

**Dump all traffics**
![proxyfor-dump](https://github.com/user-attachments/assets/eca3b38c-c2e9-404e-8990-e34feee7ae3c)

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

## Proxy Type

### Forward Proxy

The client sets the proxy to `http://127.0.0.1:8080`.

```sh
$ proxyfor
$ curl -x http://127.0.0.1:8080 httpbin.org/ip
```

### Reverse Proxy

The client directly requests `http://127.0.0.1:8080`.

**This mode is suitable for scenarios where client cannot set a proxy.**

```sh
$ proxyfor https://httpbin.org
$ curl http://127.0.0.1:8080/ip
```

## Command Line

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

You can select different interfaces with the following commands:

```sh
proxyfor                   # Enter TUI
proxyfor --web             # Serve WebUI
proxyfor --dump            # Dump all traffics
proxyfor --web --tui       # Serve WebUI + Enter TUI
proxyfor --web --dump      # Serve WebUI + Dump all traffics
proxyfor > proxyfor.md     # Dump all traffics to markdown file
```

###  Changing IP and Port

You can specify different listening addresses:

```sh
proxyfor -l 18080
proxyfor -l 127.0.0.1
proxyfor -l 127.0.0.1:18080
```

### Filtering Traffic

Filter traffic by setting method and URI:

```sh
proxyfor -f httpbin.org/ip -f httpbin.org/anything
proxyfor -f '/^(get|post) https:\/\/httpbin.org/'       
```

Filter traffic based on content type:

```sh
proxyfor -m application/json -m application/ld+json
proxyfor -m text/
```


## CA Certificates

Proxyfor can decrypt encrypted traffic on the fly, as long as the client trusts proxyfor’s built-in certificate authority. Usually this means that the proxyfor CA certificate has to be installed on the client device.

By far the easiest way to [install the proxyfor CA certificate](./assets/install-certificate.md) is to use the built-in certificate installation app.
To do this, start proxyfor and configure your target device with the correct proxy settings.
Now start a browser on the device, and visit the magic domain [proxyfor.local](http://proxyfor.local).

![proxyfor.local](https://github.com/sigoden/proxyfor/assets/4012553/a5276872-8ab1-4794-9e97-ac7038ca5e4a)

## License

Copyright (c) 2024-∞ proxyfor-developers.

Proxyfor is made available under the terms of either the MIT License or the Apache License 2.0, at your option.

See the LICENSE-APACHE and LICENSE-MIT files for license details.