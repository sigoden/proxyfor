# forproxy

[![CI](https://github.com/sigoden/forproxy/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/forproxy/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/forproxy.svg)](https://crates.io/crates/forproxy)

A CLI tool to proxy and analyze HTTP/HTTPS connections.

## Installation

### With cargo

```
cargo install git://github.com/sigoden/forproxy
```

### Binaries on macOS, Linux, Windows

Download from [Github Releases](https://github.com/sigoden/forproxy/releases), unzip and add forproxy to your $PATH.

## Usage

### Proxy mode

The client sets the proxy to `http://localhost:8080` for forproxy to analyze the connections.

```sh
$ forproxy
$ curl -x http://localhost:8080 httpbin.org/ip
```

![proxy-mode](https://github.com/sigoden/forproxy/assets/4012553/3649172b-5f8c-40ee-8600-d965eeecc924)

### Forward mode

**This mode is suitable for scenarios where a proxy cannot be set.**

The client directly requests `http://localhost:8080`, and forproxy forwards the request to `https://httpbin.org`.

```sh
$ forproxy httpbin.org/ip
$ curl http://localhost:8080/ip
```

![forward-mode](https://github.com/sigoden/forproxy/assets/4012553/74e54b98-92fb-45bb-8d87-3f18e3596a00)

# CLI

```
Usage: forproxy [OPTIONS] [URL]

Arguments:
  [URL]  Forward target

Options:
  -b, --bind <ADDR>           Specify address to listen on [default: 0.0.0.0]
  -p, --port <PORT>           Specify port to listen on [default: 8080]
  -f, --filters <REGEX>       Only inspect connections whose `{method} {uri}` matches the regex
  -m, --mime-filters <VALUE>  Only inspect connections whose content-type matches the value
  -h, --help                  Print help
  -V, --version               Print version
```

Change the bind address and port.

```sh
forproxy -b 127.0.0.1 -p 18080
```

Use `-f/--filters` to filter connections by title (`{method} {uri}`).

```sh
forproxy -f httpbin.org -f postman-echo.com
forproxy -f '/^(get|post) https:\/\/httpbin.org/'       
```

Use `-m/--mime-filters` to filter connections by content-type.

```
forproxy -m application/json -m application/ld+json
forproxy -m text/
```

## Certificates

Forproxy can decrypt encrypted traffic on the fly, as long as the client trusts forproxy’s built-in certificate authority. Usually this means that the forproxy CA certificate has to be installed on the client device.

The forproxy CA cert is located in `~/.forproxy` after it has been generated at the first start of forproxy.

## License

Copyright (c) 2024-∞ forproxy-developers.

Forproxy is made available under the terms of either the MIT License or the Apache License 2.0, at your option.

See the LICENSE-APACHE and LICENSE-MIT files for license details.