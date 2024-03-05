# forproxy

[![CI](https://github.com/sigoden/forproxy/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigoden/forproxy/actions/workflows/ci.yaml)
[![Crates](https://img.shields.io/crates/v/forproxy.svg)](https://crates.io/crates/forproxy)

A CLI tool to proxy and analyze HTTP/HTTPS connections.

## Installation

### With cargo

```
cargo install projclean
```

### Binaries on macOS, Linux, Windows

Download from [Github Releases](https://github.com/sigoden/forproxy/releases), unzip and add forproxy to your $PATH.

## Usage

### Proxy mode

![proxy-mode](https://github.com/sigoden/forproxy/assets/4012553/3649172b-5f8c-40ee-8600-d965eeecc924)


The client forwarded the request to forproxy by setting the proxy `http://localhost:8088`.

```
$ curl -x http://localhost:8088 httpbin.org/ip
```

### Forward mode

![forward-mode](https://github.com/sigoden/forproxy/assets/4012553/74e54b98-92fb-45bb-8d87-3f18e3596a00)

The client directly requests `http://localhost:8088`, and forproxy forwards the request to `https://httpbin.org`.

This mode is suitable for scenarios where a proxy cannot be set.

```
$ curl http://localhost:8088/ip
```

## Certificates

Forproxy can decrypt encrypted traffic on the fly, as long as the client trusts forproxy’s built-in certificate authority. Usually this means that the forproxy CA certificate has to be installed on the client device.

The forproxy CA cert is located in `~/.forproxy` after it has been generated at the first start of forproxy.

## License

Copyright (c) 2024-∞ forproxy-developers.

Forproxy is made available under the terms of either the MIT License or the Apache License 2.0, at your option.

See the LICENSE-APACHE and LICENSE-MIT files for license details.