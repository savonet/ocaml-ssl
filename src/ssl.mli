(*
 Copyright (C) 2003-2005 Samuel Mimram

 This file is part of Ocaml-ssl.

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *)

(** Functions for making encrypted communications using the Secure Socket Layer
    (SSL). These are mostly bindings to the openssl library.

    @author Samuel Mimram
*)

(* $Id$ *)

(** {1 Exceptions and errors} *)

(** An ssl error has occured (see SSL_get_error(3ssl) for details). *)
type ssl_error =
  | Error_none
  (** No error happened. This is never raised and should disappear in future
      versions. *)
  | Error_ssl
  | Error_want_read
  (** The operation did not complete; the same TLS/SSL I/O function should be
      called again later. *)
  | Error_want_write
  (** The operation did not complete; the same TLS/SSL I/O function should be
      called again later. *)
  | Error_want_x509_lookup
  (** The operation did not complete because an application callback set by
      [set_client_cert_cb] has asked to be called again.  The TLS/SSL I/O function
      should be called again later. Details depend on the application. *)
  | Error_syscall
  (** Some I/O error occurred.  The OpenSSL error queue may contain more
      information on the error. *)
  | Error_zero_return
  (** The TLS/SSL connection has been closed.  If the protocol version is SSL
      3.0 or TLS 1.0, this result code is returned only if a closure alert has
      occurred in the protocol, i.e. if the connection has been closed cleanly. Note
      that in this case [Error_zero_return] does not necessarily indicate that the
      underlying transport has been closed. *)
  | Error_want_connect
  (** The operation did not complete; the same TLS/SSL I/O function should be
      called again later. *)
  | Error_want_accept
  (** The operation did not complete; the same TLS/SSL I/O function should be
      called again later. *)

type bigarray = (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

(** The SSL method could not be initalized. *)
exception Method_error

exception Context_error

exception Cipher_error
exception Diffie_hellman_error
exception Ec_curve_error

(** The SSL server certificate could not be initialized. *)
exception Certificate_error of string

(** The SSL server private key could not be intialized. *)
exception Private_key_error of string

(** The SSL private key does not match the certificate public key. *)
exception Unmatching_keys

(** The given socket is invalid. *)
exception Invalid_socket

(** The SSL handler could not be initialized. *)
exception Handler_error

(** The connection could not be made with the SSL service. *)
exception Connection_error of ssl_error

(** Failed to accept an SSL connection. *)
exception Accept_error of ssl_error

(** An error occured while reading data. *)
exception Read_error of ssl_error

(** An error occured while writing data. *)
exception Write_error of ssl_error

(** Why did the certificate verification fail? *)
type verify_error =
  | Error_v_unable_to_get_issuer_cert
  (** The issuer certificate could not be found: this occurs if the issuer
      certificate of an untrusted certificate cannot be found.*)
  | Error_v_unable_to_get_ctl
  (** The CRL of a certificate could not be found. *)
  | Error_v_unable_to_decrypt_cert_signature
  (** The certificate signature could not be decrypted. This means that the
      actual signature value could not be determined rather than it not matching the
      expected value, this is only meaningful for RSA keys. *)
  | Error_v_unable_to_decrypt_CRL_signature
  (** The CRL signature could not be decrypted: this means that the actual
      signature value could not be determined rather than it not matching the
      expected value. Unused. *)
  | Error_v_unable_to_decode_issuer_public_key
  (** The public key in the certificate SubjectPublicKeyInfo could not be
      read. *)
  | Error_v_cert_signature_failure
  (** The signature of the certificate is invalid. *)
  | Error_v_CRL_signature_failure
  (** The signature of the certificate is invalid. *)
  | Error_v_cert_not_yet_valid
  (** The certificate is not yet valid: the notBefore date is after the current
      time. *)
  | Error_v_cert_has_expired
  (** The certificate has expired: that is the notAfter date is before the
      current time. *)
  | Error_v_CRL_not_yet_valid
  (** The CRL is not yet valid. *)
  | Error_v_CRL_has_expired
  (** The CRL has expired. *)
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
  (** The passed certificate is self signed and the same certificate cannot be
      found in the list of trusted certificates. *)
  | Error_v_self_signed_cert_in_chain
  (** The certificate chain could be built up using the untrusted certificates
      but the root could not be found locally. *)
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
  | Error_v_cert_revoked
  (** The certificate has been revoked. *)
  | Error_v_invalid_CA
  (** A CA certificate is invalid. Either it is not a CA or its extensions are
      not consistent with the supplied purpose. *)
  | Error_v_path_length_exceeded
  (** The basicConstraints pathlength parameter has been exceeded. *)
  | Error_v_invalid_purpose
  (** The supplied certificate cannot be used for the specified purpose. *)
  | Error_v_cert_untrusted
  (** The root CA is not marked as trusted for the specified purpose. *)
  | Error_v_cert_rejected
  (** The root CA is marked to reject the specified purpose. *)
  | Error_v_subject_issuer_mismatch
  (** The current candidate issuer certificate was rejected because its subject
      name did not match the issuer name of the current certificate. *)
  | Error_v_akid_skid_mismatch
  (** The current candidate issuer certificate was rejected because its subject
      key identifier was present and did not match the authority key identifier
      current certificate. *)
  | Error_v_akid_issuer_serial_mismatch
  (** The current candidate issuer certificate was rejected because its issuer
      name and serial number was present and did not match the authority key
      identifier of the current certificate. *)
  | Error_v_keyusage_no_certsign
  (** The current candidate issuer certificate was rejected because its keyUsage
      extension does not permit certificate signing. *)
  | Error_v_application_verification
  (** An application specific error. Unused. *)

(** An error occured while verifying the certificate. *)
exception Verify_error of verify_error


(** {1 Communication} *)

(** Initialize SSL functions. Should be called before calling any other
    function. The parameter [thread_safe] should be set to true if you use
    threads in you application (the same effect can achived by calling
    [Ssl_threads.init] first. *)
val init : ?thread_safe:bool -> unit -> unit

(** Retrieve a human-readable message that corresponds to the last error that
    occurred. *)
val get_error_string : unit -> string

(** Protocol used by SSL. *)
type protocol =
  | SSLv23 (** accept all possible protocols (SSLv2 if supported by openssl,
               SSLv3, TLSv1, TLSv1.1, TLSv1.2, and TLSv1.3) *)
  | SSLv3 (** only SSL v3 protocol *)
  | TLSv1 (** only TLS v1 protocol *)
  | TLSv1_1 (** only TLS v1.1 protocol *)
  | TLSv1_2 (** only TLS v1.2 protocol *)
  | TLSv1_3 (** only TLS v1.3 protocol *)

(** An SSL abstract socket. *)
type socket


(** {2 Threads} *)

(** You should not have to use those functions. They are only here for internal
    use (they are needed to make the openssl library thread-safe, see the
    [Ssl_threads] module). *)

val thread_safe : bool ref

(** {2 Contexts} *)

(** A context. A context should be created by a server or client once per
    program life-time and holds mainly default values for the SSL structures
    which are later created for the connections. *)
type context

(** Type of the context to create. *)
type context_type =
  | Client_context (** Client connections. *)
  | Server_context (** Server connections. *)
  | Both_context (** Client and server connections. *)

(** Create a context. *)
val create_context : protocol -> context_type -> context

(** [use_certificate ctx cert privkey] makes the context [ctx] use [cert] as
  * certificate's file name (in PEM format) and [privkey] as private key file
  * name. *)
val use_certificate : context -> string -> string -> unit

(** Set the callback function called to get passwords for encrypted PEM files.
  * The callback function takes a boolean argument which indicates if it's used
  * for reading/decryption ([false]) or writing/encryption ([true]).
  *)
val set_password_callback : context -> (bool -> string) -> unit

(** Set the list of CAs sent to the client when requesting a client certificate. *)
val set_client_CA_list_from_file : context -> string -> unit

(** Verification modes (see SSL_CTX_set_verify(3)). *)
type verify_mode =
  | Verify_peer
  | Verify_fail_if_no_peer_cert (** Implies [Verify_peer]. *)
  | Verify_client_once (** Implies [Verify_peer]. *)

(** A callback function for verification. Warning: this might change in the future. *)
type verify_callback

(** Client's verification callback. Warning: this might change in the future. *)
val client_verify_callback : verify_callback

(** Set verbosity of {! client_verify_callback } *)
val set_client_verify_callback_verbose : bool -> unit

(** Set the verify mode and callback, see SSL_CTX_set_verify(3).
  * Warning: this might change in the future. *)
val set_verify : context -> verify_mode list -> verify_callback option -> unit

(** Set the maximum depth for the certificate chain verification that shall be allowed. *)
val set_verify_depth : context -> int -> unit


(** {2 Ciphers} *)

(** A cipher. It holds the algorithm information for a particular cipher which
  * are a core part of the SSL/TLS protocol.*)
type cipher

(** Disable all protocols from the list.
  * Note that [SSLv23] disables both SSLv2 and SSLv3 (as opposed to all the
  * protocols).
  * *)
val disable_protocols : context -> protocol list -> unit

(** Set the list of available ciphers for a context. See man ciphers(1) for the format of the string. *)
val set_cipher_list : context -> string -> unit

(** When choosing a cipher, use the server's preferences instead of the client
  * preferences. When not set, the SSL server will always follow the clients
  * preferences. When set, the SSLv3/TLSv1 server will choose following its
  * own preferences. Because of the different protocol, for SSLv2 the server
  * will send its list of preferences to the client and the client chooses.*)
val honor_cipher_order : context -> unit

(** Init DH parameters from file *)
val init_dh_from_file : context -> string -> unit

(** Init EC curve from curve name *)
val init_ec_from_named_curve : context -> string -> unit

(** Get the cipher used by a socket. *)
val get_cipher : socket -> cipher

(** Get a description of a cipher. *)
val get_cipher_description : cipher -> string

(** Get the name of a cipher. *)
val get_cipher_name : cipher -> string

(** Get the version of a cipher. *)
val get_cipher_version : cipher -> string


(** {2 Certificates} *)

(** A certificate. *)
type certificate

(** [read_certificate fname] reads the certificate in the file [fname]. *)
val read_certificate : string -> certificate

val write_certificate : string -> certificate -> unit

(** Get the certificate used by a socket. *)
val get_certificate : socket -> certificate

(** Get the issuer of a certificate. *)
val get_issuer : certificate -> string

(** Get the subject of a certificate. *)
val get_subject : certificate -> string

(** [load_verify_locations ctxt cafile capath] specifies the locations for the
    context [ctx], at which CA certificates for verification purposes are
    located. [cafile] should be the name of a CA certificates file in PEM format
    and [capath] should be the name of a directory which contains CA certificates
    in PEM format. Empty strings can be used in order not to specify on of the
    parameters (but not both).

    @raise Invalid_argument if both strings are empty or if one of the files
    given in arguments could not be found. *)
val load_verify_locations : context -> string -> string -> unit

(** Specifies that the default locations from which CA certificates are loaded
    should be used. Returns [true] on success. *)
val set_default_verify_paths : context -> bool

(** Get the verification result. *)
val get_verify_result : socket -> int


(** {2 Creating, connecting and closing sockets} *)

(** Embed a Unix socket into an SSL socket. *)
val embed_socket : Unix.file_descr -> context -> socket

(** Open an SSL connection. *)
val open_connection : protocol -> Unix.sockaddr -> socket

(** Open an SSL connection with the specified context. *)
val open_connection_with_context : context -> Unix.sockaddr -> socket

(** Close an SSL connection opened with [open_connection]. *)
val shutdown_connection : socket -> unit

(** Set the hostname the client is attempting to connect to using the Server
  * Name Indication (SNI) TLS extension. *)
val set_client_SNI_hostname : socket -> string -> unit

(** Connect an SSL socket. *)
val connect : socket -> unit

(** Accept an SSL connection. *)
val accept : socket -> unit

(** Flush an SSL connection. *)
val flush : socket -> unit

(** Close an SSL connection. *)
val shutdown : socket -> unit


(** {2 I/O on SSL sockets} *)

(** Check the result of the verification of the X509 certificate presented by
    the peer, if any. Raises a [verify_error] on failure. *)
val verify : socket -> unit

(** Get the file descriptor associated with a socket. It is primarly useful for
    [select]ing on it; you should not write or read on it. *)
val file_descr_of_socket : socket -> Unix.file_descr

(** [read sock buf off len] receives data from a connected SSL socket. *)
val read : socket -> Bytes.t -> int -> int -> int

(** [read_into_bigarray sock ba off len] receives data from a connected SSL socket.
    This function releases the runtime while the read takes place. *)
val read_into_bigarray : socket -> bigarray -> int -> int -> int

(** [read_into_bigarray_blocking sock ba off len] receives data from a
    connected SSL socket.
    This function DOES NOT release the runtime while the read takes place: it
    must be used with nonblocking sockets. *)
val read_into_bigarray_blocking : socket -> bigarray -> int -> int -> int

(** [write sock buf off len] sends data over a connected SSL socket. *)
val write : socket -> Bytes.t -> int -> int -> int

(** [write_substring sock str off len] sends data over a connected SSL socket. *)
val write_substring : socket -> string -> int -> int -> int

(** [write_bigarray sock ba off len] sends data over a connected SSL socket.
    This function releases the runtime while the read takes place.
  *)
val write_bigarray : socket -> bigarray -> int -> int -> int

(** [write_bigarray sock ba off len] sends data over a connected SSL socket.
    This function DOES NOT release the runtime while the read takes place: it
    must be used with nonblocking sockets.
  *)
val write_bigarray_blocking : socket -> bigarray -> int -> int -> int


(** {3 High-level communication functions} *)

(** Input a string on an SSL socket. *)
val input_string : socket -> string

(** Write a string on an SSL socket. *)
val output_string : socket -> string -> unit

(** Input a character on an SSL socket. *)
val input_char : socket -> char

(** Write a char on an SSL socket. *)
val output_char : socket -> char -> unit

(** Input an integer on an SSL socket. *)
val input_int : socket -> int

(** Write an integer on an SSL socket. *)
val output_int : socket -> int -> unit
