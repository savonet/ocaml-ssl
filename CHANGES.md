Unreleased
=====

- Raise an error when `Ssl.flush` isn't successful (#104, #120)
- Add an API-compatible `Ssl.Runtime_lock` module. The functions in this module
  don't release the OCaml runtime lock. While they don't allow other OCaml
  threads to run concurrently, they don't perform any copying in the underlying
  data, leading certain workloads to be faster than their counterparts that
  release the lock. (#106)
- Guarantee `Ssl.output_string` writes the whole string by retrying the
  operation with unwritten bytes (#103, #116)
- Fix calls in C stubs that need to call `ERR_clear_error` before the underlying
  OpenSSL call (#118)

0.5.13 (2022-10-20)
=====

- Add `Ssl.close_notify` to perform a one-way shutdown (#63, #96).

0.5.12 (2022-08-12)
=====

- Add a few verification functions (#71):
  - `add_extra_chain_cert` to send additional chain certificates to the peer.
  - `add_cert_to_store`: to allow verification of the peer certificate CA.
  - `set_ip`: sets the expected IP address to be verified on an SSL socket.
- Improve `use_certificate_from_string` (#71) to read any type of key (rather
  than just RSA).
- Fix a segmentation fault in the ALPN selection callback under OCaml 5 (#89).
- Audit the C FFI and add `CAMLparamX` and `CAMLreturn` calls (#90).

0.5.11 (2022-07-24)
=====

- Add `digest` function (#65, #66).
- Restore compatibility with openssl < 1.1.0 (#73).
- Improved compatibility with OCaml 5 (#79).
- Fix `client_verify_callback` for `NO_NAKED_POINTERS` mode. A user-provided
  verification function in C remains an out-of-heap pointer for 4.x for
  compatibility, but is boxed for OCaml 5.x or 4.x when configured with
  `--disable-naked-pointers`. (#83)

0.5.10 (2021-02-01)
======

- Add `use_certificate_from_string` (#54).
- Add `get_verify_error_string`, `get_start_date`, `get_expiration_date` (#57).
- Release master lock on ALPN failure (#58).
- Add `version` (#60).
- Switch to dune 2 (#61).

0.5.9 (2019-07-15)
=====
- Backward compatibility with OpenSSL 1.0.2 (#53).

0.5.8 (2019-07-03)
=====
- Better error reporting.
- Add support for hostname validation (#49).
- Add ALPN support (#37, #38, #48).

0.5.7 (2018-10-25)
=====
- Correctly set #defines (#40).
- Correctly deal with non-existent directories for Homebrew (#42).

0.5.6 (2018-09-12)
=====
- Switch to the dune build system.

0.5.5 (2017-10-13)
=====
- Make sure that LDFLAGS is honored during build.

0.5.4 (2017-10-02)
=====
- Enable safe-string compatibility (#32).
- Add -std=c99 to CFLAGS (#29).

0.5.3 (2016-11-08)
=====
- Remove -ansi flag to be compatible with OCaml 4.04 (thanks Mark Shinwell).
- Use accessor functions for X509_STORE_CTX.
- Change CLIBS order to allow static linking.

0.5.2 (2015-11-23)
=====
- Add OPENSSL_NO_SSL3 preprocessor flag to disable SSLv3 (thanks Jérémie
  Courrèges-Anglas).

0.5.1 (2015-05-27)
=====
- Fix META file for versions of OCaml older than 4.02.0 (thanks Anil
  Madhavapeddy, closes #20).

0.5.0 (2015-05-18)
=====
- Allow to honor server cipher preferences (thanks mfp, closes #18).
- Add functions for reading into/writing from bigarrays, avoiding copy (thanks
  mfp, closes #15).
- Support disabling SSL protocol versions (thanks Edwin Török, closes #13).
- Use Bytes instead of String for read and write, changes the ABI thus the
  version bump (thanks Vincent Bernardoff, closes #16, and mfp, closes #19).
- Make verbosity of client_verify_callback configurable (thanks Nicolas Trangez,
  closes #12).
- Fix build with old versions of SSL (thanks Edwin Török, closes #10).

0.4.7 (2014-04-21)
=====

- Add support for TLS1.1 and TLS1.2 (thanks Thomas Calderon).
- Add function to initialize Diffie-Hellman and elliptic curve parameters
  (thanks Thomas Calderon and Edwin Török).
- Add set_client_SNI_hostname to specify client-side SNI hostname (thanks
  Mauricio Fernandez).
- Fix double leave of blocking section in ocaml_ssl_accept (thanks Edwin Török).
- Check for errors in SSL_connect/SSL_accept (thanks Jérôme Vouillon).
- Clear the error queue before calling SSL_read and similar functions;
  SSL_get_error does not work reliably otherwise (thanks Jérôme Vouillon).
- Allow static linking on Mingw64 (thanks schadinger).

0.4.6 (2011-10-16)
=====
- Added write_certificate function.
- Remove support for SSLv2, which was dropped upstream (thanks Dario Teixeira).
- Added support for compiling under Win32 (thanks David Allsopp), see
  README.win32.
- Check for pthreads in configure.

0.4.5 (2011-03-01)
=====
- Use pthread mutexes for locking thread-safe version of ssl.

0.4.4 (2010-01-06)
=====
- Use SSL_CTX_use_certificate_chain_file instead of
  SSL_CTX_use_certificate_file.
- Added support for --enable-debugging configure option.
- Don't link with unix library and don't build in custom mode.

0.4.3 (2008-12-18)
=====
- Don't use blocking sections in finalizers since it causes segfaults (thanks
  Grégoire Henry and Stéphane Glondu).

0.4.2 (2007-03-29)
=====
- Added some missing blocking sections (reported by Oscar Hellström).

0.4.1 (2007-02-21)
=====
- file_descr_of_socket is not marked as deprecated anymore.
- Patched the Makefile to be compatible with FreeBSD (thanks Jaap Boender).
- Explicitly link with libcrypto since we use it. Compilation should now work
  on Mac OS X too (thanks Janne Hellsten).

0.4.0 (2006-09-09)
=====
- Using caml_alloc_custom and Data_custom_val to access custom blocks.
- Added set_password_callback function.
- Integrated a big patch from Chris Waterson:
- Added get_error_string function.
- Read and write are not blocking anymore, use Unix.select and
  file_descr_of_socket if you want blocking functions.
- Fix SSL_CTX initialization to call SSL_CTX_set_mode(3) with
  SSL_MODE_AUTO_RETRY flag. This causes SSL_read and SSL_write to "hide" the
  SSL_ERROR_WANT_(READ|WRITE) errors that may occur during renegotiation on a
  blocking socket.
- Fix SSL_CTX initialization to call SSL_CTX_set_mode(3) with
  SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER flag. This allows for a different buffer
  address to be passed to a restarted non-blocking write operation, which is
  useful since the OCaml garbage collector may move buffers around between
  calls.
- We do not need to store explicitly the file descriptor for SSL sockets.
- Corrected checking of errors in ocaml_ssl_read (thanks Vincent Balat and
  Nataliya Guts).
- input_char now raises End_of_file when no byte could be read (thanks Nataliya
  Guts).

0.3.1 (2005-07-21)
=====
- The library is now under the LGPL licence + linking exception + linking with
  openssl exception (see COPYING for more details).

0.3.0 (2005-06-01)
=====
- Added Ssl_threads.init function to make the library thread-safe.
- Put connect, accept and flush (and all other functions) in blocking_section to
  allow other threads to run in the meantime.
- Unified the three context creation functions in create_context, the
  certificate to use should now be specified with use_certificate (sorry for the
  API-breakage).
- Added the get_verify_result function.
- Using Store_field instead of Field(...) = ...
- Using caml namespace functions.

0.2.0 (2004-12-18)
=====
- Many thanks to Thomas Fischbacher for his patches:
- Corrected int / val bugs when raising exceptions from C (those where found by
  Mike Furr too, thanks).
- Added many functions (but in Caml instead of C).
- Context creation functions now take the protocol as argument.
- Added the create_context function (for client and server connections).
- Added functions for verifying certificates: client_verify_callback,
  set_verify, set_verify_depth, verify.
- The cipher now has its own type.
- Added functions to handle ciphers: get_current_cipher, get_cipher_description,
  get_cipher_name, get_cipher_version, set_cipher_list.
- Added the read_certificate and load_verify_locations functions.
- Added the open_connection_with_context and flush functions.
- read and write functions are now thread-safe.
- Cleaned the stubs (function prototypes, comments, etc.).
- Updated OCamlMakefile and improved build system.

0.1.0 (2004-02-05)
=====
- Initial release.
