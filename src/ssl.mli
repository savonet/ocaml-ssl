(* Copyright (C) 2003-2005 Samuel Mimram

   This file is part of Ocaml-ssl.

   This library is free software; you can redistribute it and/or modify it under
   the terms of the GNU Lesser General Public License as published by the Free
   Software Foundation; either version 2.1 of the License, or (at your option)
   any later version.

   This library is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
   FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
   details.

   You should have received a copy of the GNU Lesser General Public License
   along with this library; if not, write to the Free Software Foundation, Inc.,
   51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA *)

(** Functions for making encrypted communications using the Secure Socket Layer
    (SSL). These are mostly bindings to the openssl library.

    @author Samuel Mimram *)

(** {1 OpenSSL version} *)

type version =
  { major : int  (** major version *)
  ; minor : int  (** minor version *)
  ; patch : int  (** patch number *)
  }
(** in version prior to 3.0, details are dropped: 1.1.1n = 1.1.1f *)

val native_library_version : version

(** {1 Exceptions and errors} *)

(** An ssl error has occurred (see SSL_get_error(3ssl) for details). *)
type ssl_error =
  | Error_none
      (** No error happened. This is never raised and should disappear in future
          versions. *)
  | Error_ssl
      (** A non-recoverable, fatal error in the SSL library occurred, usually a
          protocol error. The OpenSSL error queue contains more information on
          the error. If this error occurs then no further I/O operations should
          be performed on the connection and SSL_shutdown() must not be called. *)
  | Error_want_read
      (** The operation did not complete; the same TLS/SSL I/O function should
          be called again later. *)
  | Error_want_write
      (** The operation did not complete; the same TLS/SSL I/O function should
          be called again later. *)
  | Error_want_x509_lookup
      (** The operation did not complete because an application callback set by
          [set_client_cert_cb] has asked to be called again. The TLS/SSL I/O
          function should be called again later. Details depend on the
          application. *)
  | Error_syscall
      (** Some I/O error occurred. The OpenSSL error queue may contain more
          information on the error. *)
  | Error_zero_return
      (** The TLS/SSL connection has been closed. If the protocol version is SSL
          3.0 or TLS 1.0, this result code is returned only if a closure alert
          has occurred in the protocol, i.e. if the connection has been closed
          cleanly. Note that in this case [Error_zero_return] does not
          necessarily indicate that the underlying transport has been closed. *)
  | Error_want_connect
      (** The operation did not complete; the same TLS/SSL I/O function should
          be called again later. *)
  | Error_want_accept
      (** The operation did not complete; the same TLS/SSL I/O function should
          be called again later. *)
  | Error_want_async
      (** The operation did not complete because an asynchronous engine is still
          processing data. The TLS/SSL I/O function should be called again
          later. The function must be called from the same thread that the
          original call was made from. *)
  | Error_want_async_job
      (** The asynchronous job could not be started because there were no async
          jobs available in the pool. The application should retry the operation
          after a currently executing asynchronous operation for the current
          thread has completed. *)
  | Error_want_client_hello_cb
      (** The operation did not complete because an application callback set by
          SSL_CTX_set_client_hello_cb() has asked to be called again. The
          TLS/SSL I/O function should be called again later. Details depend on
          the application. *)
  | Error_want_retry_verify
      (** See
          https://www.openssl.org/docs/manmaster/man3/SSL_CTX_set_verify.html *)

type bigarray =
  (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

exception Method_error
(** The SSL method could not be initialized. *)

exception Context_error
exception Cipher_error
exception Diffie_hellman_error
exception Ec_curve_error

exception Certificate_error of string
(** The SSL server certificate could not be initialized. *)

exception Crl_error of string
(** The CRL could not be initialized. *)

exception Private_key_error of string
(** The SSL server private key could not be initialized. *)

exception Unmatching_keys
(** The SSL private key does not match the certificate public key. *)

exception Invalid_socket
(** The given socket is invalid. *)

exception Handler_error
(** The SSL handler could not be initialized. *)

exception Connection_error of ssl_error
(** The connection could not be made with the SSL service. *)

exception Accept_error of ssl_error
(** Failed to accept an SSL connection. *)

exception Read_error of ssl_error
(** An error occurred while reading data. *)

exception Write_error of ssl_error
(** An error occurred while writing data. *)

exception Flush_error of bool
(** An error occurred while flushing a socket. [Flush_error true] means that the
    operation should be retried. *)

(** Why did the certificate verification fail? *)
type verify_error =
  | Error_v_unable_to_get_issuer_cert
      (** The issuer certificate could not be found: this occurs if the issuer
          certificate of an untrusted certificate cannot be found.*)
  | Error_v_unable_to_get_ctl
      (** The CRL of a certificate could not be found. *)
  | Error_v_unable_to_decrypt_cert_signature
      (** The certificate signature could not be decrypted. This means that the
          actual signature value could not be determined rather than it not
          matching the expected value, this is only meaningful for RSA keys. *)
  | Error_v_unable_to_decrypt_CRL_signature
      (** The CRL signature could not be decrypted: this means that the actual
          signature value could not be determined rather than it not matching
          the expected value. Unused. *)
  | Error_v_unable_to_decode_issuer_public_key
      (** The public key in the certificate SubjectPublicKeyInfo could not be
          read. *)
  | Error_v_cert_signature_failure
      (** The signature of the certificate is invalid. *)
  | Error_v_CRL_signature_failure
      (** The signature of the certificate is invalid. *)
  | Error_v_cert_not_yet_valid
      (** The certificate is not yet valid: the notBefore date is after the
          current time. *)
  | Error_v_cert_has_expired
      (** The certificate has expired: that is the notAfter date is before the
          current time. *)
  | Error_v_CRL_not_yet_valid  (** The CRL is not yet valid. *)
  | Error_v_CRL_has_expired  (** The CRL has expired. *)
  | Error_v_error_in_cert_not_before_field
      (** The certificate notBefore field contains an invalid time. *)
  | Error_v_error_in_cert_not_after_field
      (** The certificate notAfter field contains an invalid time. *)
  | Error_v_error_in_CRL_last_update_field
      (** The CRL lastUpdate field contains an invalid time. *)
  | Error_v_error_in_CRL_next_update_field
      (** The CRL nextUpdate field contains an invalid time. *)
  | Error_v_out_of_mem
      (** An error occurred trying to allocate memory. This should never happen. *)
  | Error_v_depth_zero_self_signed_cert
      (** The passed certificate is self signed and the same certificate cannot
          be found in the list of trusted certificates. *)
  | Error_v_self_signed_cert_in_chain
      (** The certificate chain could be built up using the untrusted
          certificates but the root could not be found locally. *)
  | Error_v_unable_to_get_issuer_cert_locally
      (** The issuer certificate of a locally looked up certificate could not be
          found. This normally means the list of trusted certificates is not
          complete. *)
  | Error_v_unable_to_verify_leaf_signature
      (** No signatures could be verified because the chain contains only one
          certificate and it is not self signed. *)
  | Error_v_cert_chain_too_long
      (** The certificate chain length is greater than the supplied maximum
          depth. Unused. *)
  | Error_v_cert_revoked  (** The certificate has been revoked. *)
  | Error_v_invalid_CA
      (** A CA certificate is invalid. Either it is not a CA or its extensions
          are not consistent with the supplied purpose. *)
  | Error_v_path_length_exceeded
      (** The basicConstraints pathlength parameter has been exceeded. *)
  | Error_v_invalid_purpose
      (** The supplied certificate cannot be used for the specified purpose. *)
  | Error_v_cert_untrusted
      (** The root CA is not marked as trusted for the specified purpose. *)
  | Error_v_cert_rejected
      (** The root CA is marked to reject the specified purpose. *)
  | Error_v_subject_issuer_mismatch
      (** The current candidate issuer certificate was rejected because its
          subject name did not match the issuer name of the current certificate. *)
  | Error_v_akid_skid_mismatch
      (** The current candidate issuer certificate was rejected because its
          subject key identifier was present and did not match the authority key
          identifier current certificate. *)
  | Error_v_akid_issuer_serial_mismatch
      (** The current candidate issuer certificate was rejected because its
          issuer name and serial number was present and did not match the
          authority key identifier of the current certificate. *)
  | Error_v_keyusage_no_certsign
      (** The current candidate issuer certificate was rejected because its
          keyUsage extension does not permit certificate signing. *)
  | Error_v_application_verification
      (** An application specific error. Unused. *)

exception Verify_error of verify_error
(** An error occurred while verifying the certificate. *)

(** {1 Communication} *)

val init : ?thread_safe:bool -> unit -> unit
(** Initialize SSL functions. Should be called before calling any other
    function. The parameter [thread_safe] should be set to true if you use
    threads in you application (the same effect can achieved by calling
    [Ssl_threads.init] first. *)

val get_error_string : unit -> string
  [@@ocaml.alert deprecated "Use [Ssl.Error.get_error] instead"]
(** Retrieve a human-readable message that corresponds to the earliest error
    code from the thread's error queue and removes the entry. *)

module Error : sig
  type t = private
    { library_number : int
          (** Identifies the OpenSSL sub-library that generated this error.
              Library values are defined in
              https://github.com/openssl/openssl/blob/openssl-3.0.0/include/openssl/err.h.in#L72 *)
    ; reason_code : int
          (** The reason code is the information about what went wrong. *)
    ; lib : string option  (** The library name that generated the error. *)
    ; reason : string option  (** The reason string for the error message. *)
    }
  (** The error code returned by ERR_get_error() consists of a library number,
      function code and reason code.

      Each sub-library of OpenSSL has a unique library number; function and
      reason codes are unique within each sub-library. Note that different
      libraries may use the same value to signal different functions and
      reasons. *)

  val get_error : unit -> t
  (** Retrieve the earliest error from the error queue then it removes the
      entry. Returns the code and library and reason strings *)

  val peek_error : unit -> t
  (** Retrieve the earliest error from the error queue without modifying it.
      Returns the code and library and reason strings *)

  val peek_last_error : unit -> t
  (** Retrieves the latest error code from the thread's error queue without
      modifying it. Returns the code and library and reason strings. *)
end

(** Protocol used by SSL. *)
type protocol =
  | SSLv23
      [@ocaml.alert deprecated "SSL 2.0 was deprecated in 2011 by RFC 6176."]
      (** accept all possible protocols (SSLv2 if supported by openssl, SSLv3,
          TLSv1, TLSv1.1, TLSv1.2, and TLSv1.3) *)
  | SSLv3
      [@ocaml.alert
        deprecated "SSL 3.0 was deprecated in June 2015 by RFC 7568."]
      (** only SSL v3 protocol *)
  | TLSv1
      [@ocaml.alert
        deprecated
          "TLS 1.0 and 1.1 were formally deprecated in RFC8996 in March 2021."]
      (** only TLS v1 protocol *)
  | TLSv1_1
      [@ocaml.alert
        deprecated
          "TLS 1.0 and 1.1 were formally deprecated in RFC8996 in March 2021."]
      (** only TLS v1.1 protocol *)
  | TLSv1_2  (** only TLS v1.2 protocol *)
  | TLSv1_3  (** only TLS v1.3 protocol *)

type socket
(** An SSL abstract socket. *)

(** {2 Threads} *)

(** You should not have to use those functions. They are only here for internal
    use (they are needed to make the openssl library thread-safe, see the
    [Ssl_threads] module). *)

val thread_safe : bool ref

(** {2 Contexts} *)

type context
(** A context. A context should be created by a server or client once per
    program life-time and holds mainly default values for the SSL structures
    which are later created for the connections. *)

(** Type of the context to create. *)
type context_type =
  | Client_context  (** Client connections. *)
  | Server_context  (** Server connections. *)
  | Both_context  (** Client and server connections. *)

val create_context : protocol -> context_type -> context
(** Create a context. *)

val set_min_protocol_version : context -> protocol -> unit
(** [set_min_protocol_version ctx proto] sets the minimum supported protocol
    version for [ctx] to [proto]. *)

val set_max_protocol_version : context -> protocol -> unit
(** [set_max_protocol_version ctx proto] sets the maximum supported protocol
    version for [ctx] to [proto]. *)

val get_min_protocol_version : context -> protocol
(** [get_min_protocol_version ctx] sets the minimum supported protocol version
    for [ctx] to [proto]. *)

val get_max_protocol_version : context -> protocol
(** [get_max_protocol_version ctx proto] sets the maximum supported protocol
    version for [ctx] to [proto]. *)

val add_extra_chain_cert : context -> string -> unit
(** Add an additional certificate to the extra chain certificates associated
    with the [ctx]. Extra chain certificates will be sent to the peer for
    verification and are sent in order following the end entity certificate. The
    value should be contents of the certificate as string in PEM format. *)

val add_cert_to_store : context -> string -> unit
(** Add a certificate to the [ctx] trust storage. The value should be contents
    of the certificate as string in PEM format. *)

val add_crl_to_store : context -> string -> unit
(** Add a CRL to the [ctx] trust storage. The value should be contents 
    of the CRL as string in PEM format. *)

val use_certificate : context -> string -> string -> unit
(** [use_certificate ctx cert privkey] makes the context [ctx] use [cert] as *
    certificate's file name (in PEM format) and [privkey] as private key file *
    name. *)

val use_certificate_from_string : context -> string -> string -> unit
(** Use a certificate whose contents is given as argument (you should use
    instead [use_certificate] if you want to read the certificate from a file). *)

val set_password_callback : context -> (bool -> string) -> unit
(** Set the callback function called to get passwords for encrypted PEM files. *
    The callback function takes a boolean argument which indicates if it's used
    * for reading/decryption ([false]) or writing/encryption ([true]). *)

val set_client_CA_list_from_file : context -> string -> unit
(** Set the list of CAs sent to the client when requesting a client certificate. *)

(** Verification modes (see SSL_CTX_set_verify(3)). *)
type verify_mode =
  | Verify_peer
  | Verify_fail_if_no_peer_cert  (** Implies [Verify_peer]. *)
  | Verify_client_once  (** Implies [Verify_peer]. *)

type verify_callback
(** A callback function for verification. Warning: this might change in the
    future. *)

val client_verify_callback : verify_callback
(** Client's verification callback. Warning: this might change in the future. *)

val set_client_verify_callback_verbose : bool -> unit
(** Set verbosity of {! client_verify_callback } *)

val set_verify : context -> verify_mode list -> verify_callback option -> unit
(** Set the verify mode and callback, see SSL_CTX_set_verify(3). * Warning: this
    might change in the future. *)

val set_verify_depth : context -> int -> unit
(** Set the maximum depth for the certificate chain verification that shall be
    allowed. *)

val set_context_alpn_protos : context -> string list -> unit
(** Set the list of supported ALPN protocols for negotiation to the context. *)

val set_context_alpn_select_callback :
   context
  -> (string list -> string option)
  -> unit
(** Set the callback to allow server to select the preferred protocol from
    client's available protocols. *)

(** {2 Ciphers} *)

type cipher
(** A cipher. It holds the algorithm information for a particular cipher which *
    are a core part of the SSL/TLS protocol.*)

val disable_protocols : context -> protocol list -> unit
(** Disable all protocols from the list. * Note that [SSLv23] disables both
    SSLv2 and SSLv3 (as opposed to all the * protocols). * *)

val set_cipher_list : context -> string -> unit
(** Set the list of available ciphers for a context. See man ciphers(1) for the
    format of the string. *)

val honor_cipher_order : context -> unit
(** When choosing a cipher, use the server's preferences instead of the client *
    preferences. When not set, the SSL server will always follow the clients *
    preferences. When set, the SSLv3/TLSv1 server will choose following its *
    own preferences. Because of the different protocol, for SSLv2 the server *
    will send its list of preferences to the client and the client chooses.*)

val init_dh_from_file : context -> string -> unit
(** Init DH parameters from file *)

val init_ec_from_named_curve : context -> string -> unit
(** Init EC curve from curve name *)

val get_cipher : socket -> cipher
(** Get the cipher used by a socket. *)

val get_cipher_description : cipher -> string
(** Get a description of a cipher. *)

val get_cipher_name : cipher -> string
(** Get the name of a cipher. *)

val get_cipher_version : cipher -> string
(** Get the version of a cipher. *)

val version : socket -> protocol
(** Get the version used for the connection. As per the
    {{:https://www.openssl.org/docs/man1.1.1/man3/SSL_get_version.html} OpenSSL
      documentation}, should only be called after the initial handshake has been
    completed. Prior to that the results returned from these functions may be
    unreliable.

    @raise Failure if the version is unknown *)

(** {2 Certificates} *)

type certificate
(** A certificate. *)

val read_certificate : string -> certificate
(** [read_certificate fname] reads the certificate in the file [fname]. *)

val write_certificate : string -> certificate -> unit

val get_certificate : socket -> certificate
(** Get the certificate used by a socket. *)

val get_issuer : certificate -> string
(** Get the issuer of a certificate. *)

val get_subject : certificate -> string
(** Get the subject of a certificate. *)

val get_start_date : certificate -> Unix.tm
(** Get the start date of a certificate. *)

val get_expiration_date : certificate -> Unix.tm
(** Get the expiration date of a certificate. *)

val load_verify_locations : context -> string -> string -> unit
(** [load_verify_locations ctxt cafile capath] specifies the locations for the
    context [ctx], at which CA certificates for verification purposes are
    located. [cafile] should be the name of a CA certificates file in PEM format
    and [capath] should be the name of a directory which contains CA
    certificates in PEM format. Empty strings can be used in order not to
    specify on of the parameters (but not both).

    @raise Invalid_argument
      if both strings are empty or if one of the files given in arguments could
      not be found. *)

val set_default_verify_paths : context -> bool
(** Specifies that the default locations from which CA certificates are loaded
    should be used. Returns [true] on success. *)

val get_verify_result : socket -> int
(** Get the verification result. *)

val get_verify_error_string : int -> string
(** Get a human readable verification error message for the verification error
    Its input should be the result of calling [get_verify_result]. *)

val digest : [ `SHA1 | `SHA256 | `SHA384 ] -> certificate -> string
(** Get the digest of the certificate as a binary string, using the SHA1, SHA256
    or SHA384 hashing algorithm. *)

(** {2 Creating, connecting, closing and configuring sockets} *)

val embed_socket : Unix.file_descr -> context -> socket
(** Embed a Unix socket into an SSL socket. *)

val set_client_SNI_hostname : socket -> string -> unit
(** Set the hostname the client is attempting to connect to using the Server *
    Name Indication (SNI) TLS extension. *)

val set_alpn_protos : socket -> string list -> unit
(** Set the list of supported ALPN protocols for negotiation to the connection. *)

val get_negotiated_alpn_protocol : socket -> string option
(** Get the negotiated protocol from the connection. *)

val verify : socket -> unit
(** Check the result of the verification of the X509 certificate presented by
    the peer, if any. Raises a [verify_error] on failure. *)

(** Flags to specify how a certificate is matched against a given host name *)
type x509_check_flag =
  | Always_check_subject
  | No_wildcards
  | No_partial_wildcards
  | Multi_label_wildcards
  | Single_label_subdomains

(* Specify how a certificate should be matched against the host name *)
val set_hostflags : socket -> x509_check_flag list -> unit


(** Flags to specify certificate verification operation*)
type x509_check_v_flag =
  | X509_v_flag_crl_check
  | X509_v_flag_crl_check_all


(* Specify how certificate verification operation should be done*)
val set_flags :
   context
  -> x509_check_v_flag list
  -> unit


(* Set the expected host name to be verified. *)
val set_host : socket -> string -> unit

val set_ip : socket -> string -> unit
(** Set the expected ip address to be verified. Ip address is dotted decimal
    quad for IPv4 and colon-separated hexadecimal for IPv6. The condensed "::"
    notation is supported for IPv6 addresses. *)

val file_descr_of_socket : socket -> Unix.file_descr
(** Get the file descriptor associated with a socket. It is primarily useful for
    [select]ing on it; you should not write or read on it. *)

(** {2 I/O on SSL sockets} *)

(** The main SSL communication functions that can block if sockets are in
    blocking mode. This set of functions releases the OCaml runtime lock, which
    can require extra copying of application data. The module [Runtime_lock]
    provided below lifts this limitation by never releasing the OCaml runtime
    lock. *)

val connect : socket -> unit
(** Connect an SSL socket. *)

val accept : socket -> unit
(** Accept an SSL connection. *)

val open_connection : protocol -> Unix.sockaddr -> socket
(** Open an SSL connection. *)

val open_connection_with_context : context -> Unix.sockaddr -> socket
(** Open an SSL connection with the specified context. *)

val close_notify : socket -> bool
(** Send close notify to the peer. This is SSL_shutdown(3). * returns [true] if
    shutdown is finished, [false] in case [close_notify] * needs to be called a
    second time. *)

val shutdown_connection : socket -> unit
(** Close an SSL connection opened with [open_connection]. *)

val shutdown : socket -> unit
(** Close a SSL connection. * Send close notify to the peer and wait for close
    notify from peer. *)

val flush : socket -> unit
(** Flush an SSL connection. *)

val read : socket -> Bytes.t -> int -> int -> int
(** [read sock buf off len] receives data from a connected SSL socket. *)

val read_into_bigarray : socket -> bigarray -> int -> int -> int
(** [read_into_bigarray sock ba off len] receives data from a connected SSL
    socket. This function releases the runtime while the read takes place. *)

val write : socket -> Bytes.t -> int -> int -> int
(** [write sock buf off len] sends data over a connected SSL socket. *)

val write_substring : socket -> string -> int -> int -> int
(** [write_substring sock str off len] sends data over a connected SSL socket. *)

val write_bigarray : socket -> bigarray -> int -> int -> int
(** [write_bigarray sock ba off len] sends data over a connected SSL socket.
    This function releases the runtime while the read takes place. *)

(** {3 High-level communication functions} *)

val input_string : socket -> string
(** Input a string on an SSL socket. *)

val output_string : socket -> string -> unit
(** Write a string on an SSL socket. *)

val input_char : socket -> char
(** Input a character on an SSL socket. *)

val output_char : socket -> char -> unit
(** Write a char on an SSL socket. *)

val input_int : socket -> int
(** Input an integer on an SSL socket. *)

val output_int : socket -> int -> unit
(** Write an integer on an SSL socket. *)

(** [Runtime_lock] is an equivalent, signature compatible, equivalent to the
    [Ssl] module, with one difference: the OCaml runtime lock isn't released
    before calling the underlying SSL primitives. Multiple systhreads cannot,
    therefore, run concurrently.

    It works well with non blocking sockets where the usual semantics apply,
    i.e. handling of `EWOULDBLOCK`, `EGAIN`, etc. Additionally, the functions in
    this module don't perform a copy of application data buffers. *)
module Runtime_lock : sig
  val connect : socket -> unit
  (** Connect an SSL socket. *)

  val accept : socket -> unit
  (** Accept an SSL connection. *)

  val open_connection : protocol -> Unix.sockaddr -> socket
  (** Open an SSL connection. *)

  val open_connection_with_context : context -> Unix.sockaddr -> socket
  (** Open an SSL connection with the specified context. *)

  val close_notify : socket -> bool
  (** Send close notify to the peer. This is SSL_shutdown(3). * returns [true]
      if shutdown is finished, [false] in case [close_notify] * needs to be
      called a second time. *)

  val shutdown_connection : socket -> unit
  (** Close an SSL connection opened with [open_connection]. *)

  val shutdown : socket -> unit
  (** Close a SSL connection. * Send close notify to the peer and wait for close
      notify from peer. *)

  val flush : socket -> unit
  (** Flush an SSL connection. *)

  val read : socket -> Bytes.t -> int -> int -> int
  (** [read sock buf off len] receives data from a connected SSL socket. *)

  val read_into_bigarray : socket -> bigarray -> int -> int -> int
  (** [read_into_bigarray sock ba off len] receives data from a connected SSL
      socket. This function releases the runtime while the read takes place. *)

  val write : socket -> Bytes.t -> int -> int -> int
  (** [write sock buf off len] sends data over a connected SSL socket. *)

  val write_substring : socket -> string -> int -> int -> int
  (** [write_substring sock str off len] sends data over a connected SSL socket. *)

  val write_bigarray : socket -> bigarray -> int -> int -> int
  (** [write_bigarray sock ba off len] sends data over a connected SSL socket.
      This function releases the runtime while the read takes place. *)

  (** {3 High-level communication functions} *)

  val input_string : socket -> string
  (** Input a string on an SSL socket. *)

  val output_string : socket -> string -> unit
  (** Write a string on an SSL socket. *)

  val input_char : socket -> char
  (** Input a character on an SSL socket. *)

  val output_char : socket -> char -> unit
  (** Write a char on an SSL socket. *)

  val input_int : socket -> int
  (** Input an integer on an SSL socket. *)

  val output_int : socket -> int -> unit
  (** Write an integer on an SSL socket. *)
end

val read_into_bigarray_blocking : socket -> bigarray -> int -> int -> int
  [@@ocaml.alert deprecated "Use [Runtime_lock.read_into_bigarray] instead"]
(** This function is deprecated. Use [Runtime_lock.read_into_bigarray] instead. *)

val write_bigarray_blocking : socket -> bigarray -> int -> int -> int
  [@@ocaml.alert deprecated "Use [Runtime_lock.write_bigarray] instead"]
(** This function is deprecated. Use [Runtime_lock.write_bigarray] instead. *)
