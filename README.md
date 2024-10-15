# Proxyfor

[![CI](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/proxyfor.svg)](https://crates.io/crates/proxyfor)
[![Docker Pulls](https://img.shields.io/docker/pulls/sigoden/proxyfor)](https://hub.docker.com/r/sigoden/proxyfor)

A proxy CLI for capturing HTTP(S) & WS(S) Traffic.

## Features

- Supports forward/reverse proxy
- Supports HTTP/HTTPS/WS/WSS protocols
- Supports filtering & searching
- Provides terminal user interface (TUI)
- Provides web user interface (WebUI)
- Provides CA certificates installation tool
- Enables export in Markdown, cURL, or HAR formats
- Captures request/response in a non-blocking, streaming way

> Proxyfor, written in Rust, is distributed as a single executable file for Windows, macOS, and Linux, requiring no further installation steps or dependencies.

## Screenshots

**Terminal User Inferace**
![proxyfor-tui](https://github.com/user-attachments/assets/87a93e09-4783-4273-85b6-002762909fc3)

**Web User Inferace**
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

## Proxy Type

### Forward Proxy

The client sets the proxy to `http://127.0.0.1:8080`.

```sh
$ proxyfor
$ curl -x http://127.0.0.1:8080 httpbin.org/ip
```

### Reverse Proxy

The client accesses to `http://127.0.0.1:8080/*`.

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
proxyfor                   # Enter TUI, equal to `proxyfor --tui`
proxyfor --web             # Serve WebUI
proxyfor --web --tui       # Serve WebUI + Enter TUI
proxyfor --dump            # Dump all traffics to console
proxyfor > proxyfor.md     # Dump all traffics to markdown file
```

###  Changing IP and Port

You can specify different listening addresses:

```sh
proxyfor -l 8081
proxyfor -l 127.0.0.1
proxyfor -l 127.0.0.1:8081
```

### Applying Filter

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