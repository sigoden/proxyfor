# Proxyfor

[![CI](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/proxyfor.svg)](https://crates.io/crates/proxyfor)

A simple and portable proxy for capturing HTTP and HTTPS traffic.

## Features

- Support forward proxy
- Support reverse proxy
- Support filtering
- Integrate web inteface
- Integrate certificates installation webapp
- Export in Markdown, cURL, or HAR formats

## Installation

### With cargo

```
cargo install proxyfor
```

### Binaries on macOS, Linux, Windows

Download from [Github Releases](https://github.com/sigoden/proxyfor/releases), unzip and add proxyfor to your $PATH.

## Usage

### Forward Proxy

The client sets the proxy to `http://127.0.0.1:8080`.

```sh
$ proxyfor
$ curl -x http://127.0.0.1:8080 httpbin.org/ip
```

![forwarding-proxy](https://github.com/sigoden/proxyfor/assets/4012553/c40cc1be-b9e9-4846-9702-ad3610719b08)

### Reverse Proxy

The client directly requests `http://127.0.0.1:8080`.

**This mode is suitable for scenarios where client cannot set a proxy.**

```sh
$ proxyfor https://httpbin.org
$ curl http://127.0.0.1:8080/ip
```


![reverse-proxy](https://github.com/sigoden/proxyfor/assets/4012553/789ad353-9fe3-4bff-9f47-f19fd8dc5ce6)

## Web Interface

Proxyfor provides a web-based user interface that allows you to interactively inspect the HTTP traffic. All traffic is kept in memory, which means that it’s intended for small-ish samples.

![proxyfor-webui](https://github.com/sigoden/proxyfor/assets/4012553/a88b5a11-5191-4b4d-ac61-5ff2e7a70a88)

## Command Line

```
Usage: proxyfor [OPTIONS] [URL]

Arguments:
  [URL]  Reverse proxy url

Options:
  -l, --listen <ADDR>         Listening ip and port address [default: 0.0.0.0:8080]
  -f, --filters <REGEX>       Only inspect http(s) traffic whose `{method} {uri}` matches the regex
  -m, --mime-filters <VALUE>  Only inspect http(s) traffic whose content-type matches the value
  -w, --web                   Enable web interface
  -h, --help                  Print help
  -V, --version               Print version
```

Change the ip and port.

```sh
proxyfor -l 18080
proxyfor -l 127.0.0.1
proxyfor -l 127.0.0.1:18080
```

Enable web inteface with `-w/--web`

```sh
proxyfor --web
```

Use `-f/--filters` to filter traffic by matching `{method} {uri}`.

```sh
proxyfor -f httpbin.org/ip -f httpbin.org/anything
proxyfor -f '/^(get|post) https:\/\/httpbin.org/'       
```

Use `-m/--mime-filters` to filter traffic by content-type.

```sh
proxyfor -m application/json -m application/ld+json
proxyfor -m text/
```

Pipe it to a markdown file, then view the captured traffic using your favorite editor/IDE with syntax highlighting, folding, search capabilities.

```sh
proxyfor > proxyfor.md
```

## Certificates

Proxyfor can decrypt encrypted traffic on the fly, as long as the client trusts proxyfor’s built-in certificate authority. Usually this means that the proxyfor CA certificate has to be installed on the client device.

By far the easiest way to [install the proxyfor CA certificate](./assets/install-certificate.md) is to use the built-in certificate installation app.
To do this, start proxyfor and configure your target device with the correct proxy settings.
Now start a browser on the device, and visit the magic domain [proxyfor.local](http://proxyfor.local).

![proxyfor.local](https://github.com/sigoden/proxyfor/assets/4012553/a5276872-8ab1-4794-9e97-ac7038ca5e4a)

## License

Copyright (c) 2024-∞ proxyfor-developers.

Proxyfor is made available under the terms of either the MIT License or the Apache License 2.0, at your option.

See the LICENSE-APACHE and LICENSE-MIT files for license details.