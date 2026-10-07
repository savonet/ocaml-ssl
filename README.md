OCaml-SSL - OCaml bindings for OpenSSL
======================================

[![LGPL license](https://img.shields.io/badge/License-LGPL-green.svg)](COPYING)
[![GitHub release](https://img.shields.io/github/release/savonet/ocaml-ssl.svg)](https://github.com/savonet/ocaml-ssl/releases/)
[![Install with Opam !](https://img.shields.io/badge/Install%20with-Opam-1abc9c.svg)](https://opam.ocaml.org/packages/ssl/)
[![Build](https://github.com/savonet/ocaml-ssl/actions/workflows/build.yml/badge.svg)](https://github.com/savonet/ocaml-ssl/actions/workflows/build.yml)

`ssl` gives OCaml programs TLS client and server sockets on top of `Unix` file
descriptors, using the system's OpenSSL.

* [API documentation](https://savonet.github.io/ocaml-ssl/ssl/Ssl/index.html)
* [Changelog](CHANGES.md)
* [Bug reports](https://github.com/savonet/ocaml-ssl/issues)

Installation
------------

```
opam install ssl
```

This requires OCaml 4.14 or later and OpenSSL 1.1.0 or later. opam installs
the OpenSSL development files through the `conf-libssl` package.

Then add `ssl` to the `libraries` field of your `dune` file.

Usage
-----

### Client

A client that verifies the server certificate against the system's CA
certificates and checks that it matches the host name:

```ocaml
let () =
  let host = "example.org" in
  let ctx = Ssl.create_context Ssl.TLSv1_3 Ssl.Client_context in
  Ssl.set_min_protocol_version ctx Ssl.TLSv1_2;
  Ssl.set_verify ctx [Ssl.Verify_peer] None;
  if not (Ssl.set_default_verify_paths ctx) then failwith "no CA certificates";
  let addr = (Unix.gethostbyname host).Unix.h_addr_list.(0) in
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.connect fd (Unix.ADDR_INET (addr, 443));
  let ssl = Ssl.embed_socket fd ctx in
  Ssl.set_client_SNI_hostname ssl host;
  Ssl.set_host ssl host;
  Ssl.connect ssl;
  Ssl.output_string ssl
    (Printf.sprintf "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
       host);
  print_string (Ssl.input_string ssl);
  Ssl.shutdown_connection ssl
```

`Ssl.create_context` pins the context to a single protocol version;
`Ssl.set_min_protocol_version` and `Ssl.set_max_protocol_version` widen it to a
range.

Certificates are not verified unless `Ssl.set_verify` asks for it, and the host
name is not checked unless `Ssl.set_host` (or `Ssl.set_ip`) is called.

### Server

A server loads its certificate and private key into the context, then calls
`Ssl.accept` on each socket accepted from its listening socket:

```ocaml
let ctx = Ssl.create_context Ssl.TLSv1_3 Ssl.Server_context in
Ssl.use_certificate ctx "cert.pem" "privkey.pem";
(* ... *)
let fd, _ = Unix.accept listening_socket in
let ssl = Ssl.embed_socket fd ctx in
Ssl.accept ssl
```

A self-signed certificate is enough to try this out:

```
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout privkey.pem -out cert.pem -subj "/CN=localhost"
```

See [`examples`](examples) for complete programs, including ALPN negotiation.

### Threads

The library is thread-safe: OpenSSL 1.1.0 and later is thread-safe on its own.
`Ssl_threads.init` and the `thread_safe` argument of `Ssl.init` do nothing and
are kept for compatibility.

The functions in `Ssl` release the OCaml runtime lock while they block.
`Ssl.Runtime_lock` offers the same functions without releasing it, which is
faster for non-blocking sockets.

### Lwt and Eio

[`lwt_ssl`](https://github.com/ocsigen/lwt_ssl) and
[`eio-ssl`](https://github.com/anmonteiro/eio-ssl) build on this library.

Development
-----------

```
opam install --deps-only --with-test .
dune build
dune runtest
```

A Nix flake is also provided: `nix develop`. See
[`tests/HACKING.md`](tests/HACKING.md) for how the test certificates are
generated.

License
-------

Copyright (c) 2003-2026 the Savonet Team.

This library is released under the LGPL version 2.1, with the OCaml linking
exception and the additional exemption that compiling, linking, and/or using
OpenSSL is allowed. See [`COPYING`](COPYING) for the full text.

The examples are under the GPL version 2.0.

This product includes software developed by the OpenSSL Project for use in the
[OpenSSL Toolkit](https://www.openssl.org/).
