# proxyfor

[![CI](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/proxyfor/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/proxyfor.svg)](https://crates.io/crates/proxyfor)

A simple and portable proxy for capturing HTTP and HTTPS traffic.

## Installation

### With cargo

```
cargo install git://github.com/sigoden/proxyfor
```

### Binaries on macOS, Linux, Windows

Download from [Github Releases](https://github.com/sigoden/proxyfor/releases), unzip and add proxyfor to your $PATH.

## Usage

### Proxy Mode

The client sets the proxy to `http://localhost:8080` for proxyfor to capture the http(s) traffic.

```sh
$ proxyfor
$ curl -x http://localhost:8080 httpbin.org/ip
```

![proxy-mode](https://github.com/sigoden/proxyfor/assets/4012553/3649172b-5f8c-40ee-8600-d965eeecc924)

### Forward Mode

**This mode is suitable for scenarios where a proxy cannot be set.**

The client directly requests `http://localhost:8080`, and proxyfor forwards the request to `https://httpbin.org`.

```sh
$ proxyfor httpbin.org/ip
$ curl http://localhost:8080/ip
```

![forward-mode](https://github.com/sigoden/proxyfor/assets/4012553/74e54b98-92fb-45bb-8d87-3f18e3596a00)

# CLI

```
Usage: proxyfor [OPTIONS] [URL]

Arguments:
  [URL]  Forward url

Options:
  -l, --listen <ADDR>         Listening ip and port address [default: 0.0.0.0:8080]
  -f, --filters <REGEX>       Only inspect http(s) traffic whose `{method} {uri}` matches the regex
  -m, --mime-filters <VALUE>  Only inspect http(s) traffic whose content-type matches the value
  -h, --help                  Print help
  -V, --version               Print version
```

Change the ip and port.

```sh
proxyfor -l 18080
proxyfor -l 127.0.0.1
proxyfor -l 127.0.0.1:18080
```

Use `-f/--filters` to filter traffic by title (`{method} {uri}`).

```sh
proxyfor -f httpbin.org -f postman-echo.com
proxyfor -f '/^(get|post) https:\/\/httpbin.org/'       
```

Use `-m/--mime-filters` to filter traffic by content-type.

```sh
proxyfor -m application/json -m application/ld+json
proxyfor -m text/
```

Pipe it to a markdown file, then analyze the captured traffic using your favorite editor/IDE with folding, navigation, search capabilities.

```sh
proxyfor > proxyfor.md
```

## Certificates

proxyfor can decrypt encrypted traffic on the fly, as long as the client trusts proxyfor’s built-in certificate authority. Usually this means that the proxyfor CA certificate has to be installed on the client device.

The proxyfor CA cert is located in `~/.proxyfor` after it has been generated at the first start of proxyfor.

## License

Copyright (c) 2024-∞ proxyfor-developers.

proxyfor is made available under the terms of either the MIT License or the Apache License 2.0, at your option.

See the LICENSE-APACHE and LICENSE-MIT files for license details.