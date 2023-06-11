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

type version =
  { major : int  (** major version *)
  ; minor : int  (** minor version *)
  ; patch : int  (** patch number (fix + patch in version < 3.0) *)
  }

external get_version : unit -> version = "ocaml_ssl_get_version"

let native_library_version : version = get_version ()

type protocol =
  | SSLv23
  | SSLv3
  | TLSv1
  | TLSv1_1
  | TLSv1_2
  | TLSv1_3

type context
type certificate
type socket

type ssl_error =
  | Error_none
  | Error_ssl
  | Error_want_read
  | Error_want_write
  | Error_want_x509_lookup
  | Error_syscall
  | Error_zero_return
  | Error_want_connect
  | Error_want_accept
  | Error_want_async
  | Error_want_async_job
  | Error_want_client_hello_cb
  | Error_want_retry_verify

type verify_error =
  | Error_v_unable_to_get_issuer_cert
  | Error_v_unable_to_get_ctl
  | Error_v_unable_to_decrypt_cert_signature
  | Error_v_unable_to_decrypt_CRL_signature
  | Error_v_unable_to_decode_issuer_public_key
  | Error_v_cert_signature_failure
  | Error_v_CRL_signature_failure
  | Error_v_cert_not_yet_valid
  | Error_v_cert_has_expired
  | Error_v_CRL_not_yet_valid
  | Error_v_CRL_has_expired
  | Error_v_error_in_cert_not_before_field
  | Error_v_error_in_cert_not_after_field
  | Error_v_error_in_CRL_last_update_field
  | Error_v_error_in_CRL_next_update_field
  | Error_v_out_of_mem
  | Error_v_depth_zero_self_signed_cert
  | Error_v_self_signed_cert_in_chain
  | Error_v_unable_to_get_issuer_cert_locally
  | Error_v_unable_to_verify_leaf_signature
  | Error_v_cert_chain_too_long
  | Error_v_cert_revoked
  | Error_v_invalid_CA
  | Error_v_path_length_exceeded
  | Error_v_invalid_purpose
  | Error_v_cert_untrusted
  | Error_v_cert_rejected
  | Error_v_subject_issuer_mismatch
  | Error_v_akid_skid_mismatch
  | Error_v_akid_issuer_serial_mismatch
  | Error_v_keyusage_no_certsign
  | Error_v_application_verification

type bigarray =
  (char, Bigarray.int8_unsigned_elt, Bigarray.c_layout) Bigarray.Array1.t

external get_error_string : unit -> string = "ocaml_ssl_get_error_string"
(** Kept for backwards compatibility *)

module Error = struct
  type t = private
    { library_number : int
    ; reason_code : int
    ; lib : string option
    ; reason : string option
    }

  type err_function =
    | Get_error
    | Peek_error
    | Peek_last_error

  external error_struct : err_function -> t = "ocaml_ssl_error_struct"

  let get_error () = error_struct Get_error
  let peek_error () = error_struct Peek_error
  let peek_last_error () = error_struct Peek_last_error

  (** Reproduces the string format from ERR_error_string_n *)
  let peek_last_error_string () =
    let err = peek_last_error () in
    let libstring = match err.lib with Some lib -> lib | None -> "lib(0)" in
    let reasonstring =
      match err.reason with Some reason -> reason | None -> "reason(0)"
    in
    Printf.sprintf
      "error:%02lX:%06lX:%s::%s"
      (Int32.of_int err.library_number)
      (Int32.of_int err.reason_code)
      libstring
      reasonstring
end

exception Method_error
exception Context_error
exception Certificate_error of string
exception Cipher_error
exception Diffie_hellman_error
exception Ec_curve_error
exception Private_key_error of string
exception Unmatching_keys
exception Invalid_socket
exception Handler_error
exception Connection_error of ssl_error
exception Accept_error of ssl_error
exception Read_error of ssl_error
exception Write_error of ssl_error
exception Verify_error of verify_error
exception Flush_error of bool (* true means retry *)

let () =
  Printexc.register_printer (function
      | Method_error -> Some "SSL: Method error"
      | Context_error -> Some "SSL: Context error"
      | Certificate_error s -> Some ("SSL: Certificate error: " ^ s)
      | Cipher_error -> Some "SSL: Cipher error"
      | Diffie_hellman_error -> Some "SSL: Diffie-Hellman error"
      | Ec_curve_error -> Some "SSL: EC curve error"
      | Private_key_error s -> Some ("SSL: Private key error: " ^ s)
      | Unmatching_keys -> Some "SSL: Unmatching keys"
      | Invalid_socket -> Some "SSL: Invalid socket"
      | Handler_error -> Some "SSL: Handler error"
      | Connection_error _ ->
        Some ("SSL connection() error: " ^ Error.peek_last_error_string ())
      | Accept_error _ ->
        Some ("SSL accept() error: " ^ Error.peek_last_error_string ())
      | Read_error _ ->
        Some ("SSL read() error: " ^ Error.peek_last_error_string ())
      | Write_error _ ->
        Some ("SSL write() error: " ^ Error.peek_last_error_string ())
      | Verify_error _ ->
        Some ("SSL verify() error: " ^ Error.peek_last_error_string ())
      | Flush_error b ->
        Some
          (Printf.sprintf "SSL flush(%b) error: " b
          ^ Error.peek_last_error_string ())
      | _ -> None)

let () =
  Callback.register_exception "ssl_exn_method_error" Method_error;
  Callback.register_exception "ssl_exn_context_error" Context_error;
  Callback.register_exception "ssl_exn_certificate_error" (Certificate_error "");
  Callback.register_exception "ssl_exn_cipher_error" Cipher_error;
  Callback.register_exception
    "ssl_exn_diffie_hellman_error"
    Diffie_hellman_error;
  Callback.register_exception "ssl_exn_ec_curve_error" Ec_curve_error;
  Callback.register_exception "ssl_exn_private_key_error" (Private_key_error "");
  Callback.register_exception "ssl_exn_unmatching_keys" Unmatching_keys;
  Callback.register_exception "ssl_exn_invalid_socket" Invalid_socket;
  Callback.register_exception "ssl_exn_handler_error" Handler_error;
  Callback.register_exception
    "ssl_exn_connection_error"
    (Connection_error Error_none);
  Callback.register_exception "ssl_exn_accept_error" (Accept_error Error_none);
  Callback.register_exception "ssl_exn_read_error" (Read_error Error_none);
  Callback.register_exception "ssl_exn_write_error" (Write_error Error_none);
  Callback.register_exception
    "ssl_exn_verify_error"
    (Verify_error Error_v_application_verification);
  Callback.register_exception "ssl_exn_flush_error" (Flush_error true)

let thread_safe = ref false

external init : bool -> unit = "ocaml_ssl_init"

let ts = thread_safe

let init ?thread_safe () =
  let thread_safe = match thread_safe with Some b -> b | None -> !ts in
  init thread_safe

type context_type =
  | Client_context
  | Server_context
  | Both_context

external create_context :
   protocol
  -> context_type
  -> context
  = "ocaml_ssl_create_context"

external set_min_protocol_version :
   context
  -> protocol
  -> unit
  = "ocaml_ssl_ctx_set_min_proto_version"

external set_max_protocol_version :
   context
  -> protocol
  -> unit
  = "ocaml_ssl_ctx_set_max_proto_version"

external get_min_protocol_version :
   context
  -> protocol
  = "ocaml_ssl_ctx_get_min_proto_version"

external get_max_protocol_version :
   context
  -> protocol
  = "ocaml_ssl_ctx_get_max_proto_version"

external add_extra_chain_cert :
   context
  -> string
  -> unit
  = "ocaml_ssl_ctx_add_extra_chain_cert"

external add_cert_to_store :
   context
  -> string
  -> unit
  = "ocaml_ssl_ctx_add_cert_to_store"

external use_certificate :
   context
  -> string
  -> string
  -> unit
  = "ocaml_ssl_ctx_use_certificate"

external use_certificate_from_string :
   context
  -> string
  -> string
  -> unit
  = "ocaml_ssl_ctx_use_certificate_from_string"

external set_password_callback :
   context
  -> (bool -> string)
  -> unit
  = "ocaml_ssl_ctx_set_default_passwd_cb"

external embed_socket :
   Unix.file_descr
  -> context
  -> socket
  = "ocaml_ssl_embed_socket"

external disable_protocols :
   context
  -> protocol list
  -> unit
  = "ocaml_ssl_disable_protocols"

external set_cipher_list :
   context
  -> string
  -> unit
  = "ocaml_ssl_ctx_set_cipher_list"

external honor_cipher_order :
   context
  -> unit
  = "ocaml_ssl_ctx_honor_cipher_order"

external init_dh_from_file :
   context
  -> string
  -> unit
  = "ocaml_ssl_ctx_init_dh_from_file"

external init_ec_from_named_curve :
   context
  -> string
  -> unit
  = "ocaml_ssl_ctx_init_ec_from_named_curve"

external load_verify_locations :
   context
  -> string
  -> string
  -> unit
  = "ocaml_ssl_ctx_load_verify_locations"

external set_default_verify_paths :
   context
  -> bool
  = "ocaml_ssl_ctx_set_default_verify_paths"

external get_verify_result : socket -> int = "ocaml_ssl_get_verify_result"

external get_verify_error_string :
   int
  -> string
  = "ocaml_ssl_get_verify_error_string"

external digest :
   [ `SHA1 | `SHA256 | `SHA384 ]
  -> certificate
  -> string
  = "ocaml_ssl_digest"

type verify_mode =
  | Verify_peer
  | Verify_fail_if_no_peer_cert
  | Verify_client_once

type verify_callback

external get_client_verify_callback_ptr :
   unit
  -> verify_callback
  = "ocaml_ssl_get_client_verify_callback_ptr"

let client_verify_callback = get_client_verify_callback_ptr ()

external set_client_verify_callback_verbose :
   bool
  -> unit
  = "ocaml_ssl_set_client_verify_callback_verbose"

external set_verify :
   context
  -> verify_mode list
  -> verify_callback option
  -> unit
  = "ocaml_ssl_ctx_set_verify"

external set_verify_depth :
   context
  -> int
  -> unit
  = "ocaml_ssl_ctx_set_verify_depth"

external set_client_CA_list_from_file :
   context
  -> string
  -> unit
  = "ocaml_ssl_ctx_set_client_CA_list_from_file"

external set_context_alpn_protos :
   context
  -> string list
  -> unit
  = "ocaml_ssl_ctx_set_alpn_protos"

external set_context_alpn_select_callback :
   context
  -> (string list -> string option)
  -> unit
  = "ocaml_ssl_ctx_set_alpn_select_callback"

external version : socket -> protocol = "ocaml_ssl_version"

type cipher

external get_cipher : socket -> cipher = "ocaml_ssl_get_current_cipher"

external get_cipher_description :
   cipher
  -> string
  = "ocaml_ssl_get_cipher_description"

(* TODO: get_cipher_bits *)

external get_cipher_name : cipher -> string = "ocaml_ssl_get_cipher_name"
external get_cipher_version : cipher -> string = "ocaml_ssl_get_cipher_version"
external get_certificate : socket -> certificate = "ocaml_ssl_get_certificate"
external read_certificate : string -> certificate = "ocaml_ssl_read_certificate"

external write_certificate :
   string
  -> certificate
  -> unit
  = "ocaml_ssl_write_certificate"

external get_issuer : certificate -> string = "ocaml_ssl_get_issuer"
external get_subject : certificate -> string = "ocaml_ssl_get_subject"
external get_start_date : certificate -> Unix.tm = "ocaml_ssl_get_start_date"

external get_expiration_date :
   certificate
  -> Unix.tm
  = "ocaml_ssl_get_expiration_date"

external file_descr_of_socket :
   socket
  -> Unix.file_descr
  = "ocaml_ssl_get_file_descr"

external set_client_SNI_hostname :
   socket
  -> string
  -> unit
  = "ocaml_ssl_set_client_SNI_hostname"

external set_alpn_protos :
   socket
  -> string list
  -> unit
  = "ocaml_ssl_set_alpn_protos"

external get_negotiated_alpn_protocol :
   socket
  -> string option
  = "ocaml_ssl_get_negotiated_alpn_protocol"

external verify : socket -> unit = "ocaml_ssl_verify"

type x509_check_flag =
  | Always_check_subject
  | No_wildcards
  | No_partial_wildcards
  | Multi_label_wildcards
  | Single_label_subdomains

external set_hostflags :
   socket
  -> x509_check_flag list
  -> unit
  = "ocaml_ssl_set_hostflags"

external set_host : socket -> string -> unit = "ocaml_ssl_set1_host"
external set_ip : socket -> string -> unit = "ocaml_ssl_set1_ip"

(* Here is the signature of the base communication functions that are
   implemented below in two versions *)
module type Ssl_base = sig
  val connect : socket -> unit
  val accept : socket -> unit
  val ssl_shutdown : socket -> bool
  val flush : socket -> unit
  val read : socket -> Bytes.t -> int -> int -> int
  val read_into_bigarray : socket -> bigarray -> int -> int -> int
  val write : socket -> Bytes.t -> int -> int -> int
  val write_substring : socket -> string -> int -> int -> int
  val write_bigarray : socket -> bigarray -> int -> int -> int
end

(* Provide the base implementation communication functions that release the
   OCaml runtime lock, allowing multiple systhreads to execute concurrently. *)
module Runtime_unlock_base = struct
  external connect : socket -> unit = "ocaml_ssl_connect"
  external accept : socket -> unit = "ocaml_ssl_accept"
  external write : socket -> Bytes.t -> int -> int -> int = "ocaml_ssl_write"

  external write_substring :
     socket
    -> string
    -> int
    -> int
    -> int
    = "ocaml_ssl_write"

  external write_bigarray :
     socket
    -> bigarray
    -> int
    -> int
    -> int
    = "ocaml_ssl_write_bigarray"

  external read : socket -> Bytes.t -> int -> int -> int = "ocaml_ssl_read"

  external read_into_bigarray :
     socket
    -> bigarray
    -> int
    -> int
    -> int
    = "ocaml_ssl_read_into_bigarray"

  external flush : socket -> unit = "ocaml_ssl_flush"
  external ssl_shutdown : socket -> bool = "ocaml_ssl_shutdown"
end

(* Same as above, but doesn't release the lock. *)
module Runtime_lock_base = struct
  external get_error : socket -> int -> ssl_error = "ocaml_ssl_get_error_code"
    [@@noalloc]

  external connect : socket -> int = "ocaml_ssl_connect_blocking" [@@noalloc]

  let connect socket =
    let ret = connect socket in
    (* From https://www.openssl.org/docs/man1.1.1/man3/SSL_connect.html:

       RETURN VALUES

       0 The TLS/SSL handshake was not successful [...]. Call SSL_get_error()
       with the return value ret to find out the reason.

       1 The TLS/SSL handshake was successfully completed [...].

       <0 The TLS/SSL handshake was not successful [...]. Call SSL_get_error()
       with the return value ret to find out the reason. *)
    if ret <> 1
    then
      let err = get_error socket ret in
      raise (Connection_error err)

  external accept : socket -> int = "ocaml_ssl_accept_blocking" [@@noalloc]

  let accept socket =
    let ret = accept socket in
    (* From https://www.openssl.org/docs/man1.1.1/man3/SSL_accept.html:

       RETURN VALUES

       0 The TLS/SSL handshake was not successful [...]. Call SSL_get_error()
       with the return value ret to find out the reason.

       1 The TLS/SSL handshake was successfully completed [...].

       <0 The TLS/SSL handshake was not successful [...]. Call SSL_get_error()
       with the return value ret to find out the reason. *)
    if ret <> 1
    then
      let err = get_error socket ret in
      raise (Accept_error err)

  external write :
     socket
    -> Bytes.t
    -> int
    -> int
    -> int
    = "ocaml_ssl_write_blocking"
    [@@noalloc]

  let write socket buffer start length =
    if start < 0 then invalid_arg "Ssl.write: start negative";
    if length < 0 then invalid_arg "Ssl.write: length negative";
    if start + length > Bytes.length buffer
    then invalid_arg "Ssl.write: Buffer too short";
    let ret = write socket buffer start length in
    (* From https://www.openssl.org/docs/man1.1.1/man3/SSL_write.html:

       RETURN VALUES

       > 0 The write operation was successful, the return value is the number of
       bytes actually written to the TLS/SSL connection.

       <= 0 The write operation was not successful [...]. Call SSL_get_error()
       with the return value ret to find out the reason. *)
    (if ret <= 0
     then
       let err = get_error socket ret in
       raise (Write_error err));
    ret

  external write_substring :
     socket
    -> string
    -> int
    -> int
    -> int
    = "ocaml_ssl_write_blocking"
    [@@noalloc]

  let write_substring socket buffer start length =
    if start < 0 then invalid_arg "Ssl.write_substring: start negative";
    if length < 0 then invalid_arg "Ssl.write_substring: length negative";
    if start + length > String.length buffer
    then invalid_arg "Ssl.write_substring: Buffer too short";
    let ret = write_substring socket buffer start length in
    (if ret <= 0
     then
       let err = get_error socket ret in
       raise (Write_error err));
    ret

  external write_bigarray :
     socket
    -> bigarray
    -> int
    -> int
    -> int
    = "ocaml_ssl_write_bigarray_blocking"
    [@@noalloc]

  let write_bigarray socket buffer start length =
    if start < 0 then invalid_arg "Ssl.write_bigarray: start negative";
    if length < 0 then invalid_arg "Ssl.write_bigarray: length negative";
    if start + length > Bigarray.Array1.dim buffer
    then invalid_arg "Ssl.write_bigarray: Buffer too short";
    let ret = write_bigarray socket buffer start length in
    (if ret <= 0
     then
       let err = get_error socket ret in
       raise (Write_error err));
    ret

  external read :
     socket
    -> Bytes.t
    -> int
    -> int
    -> int
    = "ocaml_ssl_read_blocking"
    [@@noalloc]

  let read socket buffer start length =
    if start < 0 then invalid_arg "Ssl.read: start negative";
    if length < 0 then invalid_arg "Ssl.read: length negative";
    if start + length > Bytes.length buffer then invalid_arg "Buffer too short";
    let ret = read socket buffer start length in
    (* From https://www.openssl.org/docs/man1.1.1/man3/SSL_read.html

       RETURN VALUES

       > 0 The read operation was successful. The return value is the number of
       bytes actually read from the TLS/SSL connection.

       <= 0 The read operation was not successful [...]. Call SSL_get_error(3)
       with the return value ret to find out the reason. *)
    (if ret <= 0
     then
       let err = get_error socket ret in
       raise (Read_error err));
    ret

  external read_into_bigarray :
     socket
    -> bigarray
    -> int
    -> int
    -> int
    = "ocaml_ssl_read_into_bigarray_blocking"
    [@@noalloc]

  let read_into_bigarray socket buffer start length =
    if start < 0 then invalid_arg "Ssl.read_into_big_array: start negative";
    if length < 0 then invalid_arg "Ssl.read_into_big_array: length negative";
    if start + length > Bigarray.Array1.dim buffer
    then invalid_arg "Buffer too short";
    let ret = read_into_bigarray socket buffer start length in
    (if ret <= 0
     then
       let err = get_error socket ret in
       raise (Read_error err));
    ret

  external flush : socket -> int = "ocaml_ssl_flush_blocking" [@@noalloc]

  let flush socket =
    let ret = flush socket in
    (* From https://www.openssl.org/docs/man1.1.1/man3/BIO_flush.html:

       RETURN VALUES

       BIO_flush() returns 1 for success and 0 or -1 for failure.

       Additionally, we use -2 to signal the need to retry without allocation,
       see [ssl_stubs.c]. *)
    if ret <> 1 then raise (Flush_error (ret = -2))

  external ssl_shutdown : socket -> int = "ocaml_ssl_shutdown_blocking"
    [@@noalloc]

  let ssl_shutdown socket =
    let ret = ssl_shutdown socket in
    (if ret < 0
     then
       let err = get_error socket ret in
       raise (Connection_error err));
    ret = 1
end

(* The functor implementing communication functions from a structure of type
   Ssl_base *)
module Make (Ssl_base : Ssl_base) = struct
  include Ssl_base

  let open_connection_with_context context sockaddr =
    let domain = Unix.domain_of_sockaddr sockaddr in
    let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
    try
      Unix.connect sock sockaddr;
      let ssl = embed_socket sock context in
      connect ssl;
      ssl
    with
    | exn ->
      Unix.close sock;
      raise exn

  let open_connection ssl_method sockaddr =
    open_connection_with_context
      (create_context ssl_method Client_context)
      sockaddr

  let close_notify = ssl_shutdown

  let shutdown sock =
    if not (close_notify sock) then ignore (close_notify sock : bool)

  let shutdown_connection = shutdown

  let output_string ssl s =
    let len = String.length s in
    let to_write = ref len in
    let offset = ref 0 in
    while !to_write > 0 do
      let written = write_substring ssl s !offset !to_write in
      if written <= 0 then failwith "output_string failed to write";
      to_write := !to_write - written;
      offset := !offset + written
    done

  let output_char ssl c =
    let tmp = String.make 1 c in
    let written = write_substring ssl tmp 0 1 in
    if written <= 0 then failwith "output_char failed to write"

  let output_int ssl i =
    let tmp = Bytes.create 4 in
    Bytes.set tmp 0 (char_of_int (i lsr 24));
    Bytes.set tmp 1 (char_of_int ((i lsr 16) land 0xff));
    Bytes.set tmp 2 (char_of_int ((i lsr 8) land 0xff));
    Bytes.set tmp 3 (char_of_int (i land 0xff));
    if write ssl tmp 0 4 <> 4
    then failwith "output_int error: all the byte were not sent"

  let input_string ssl =
    let bufsize = 1024 in
    let buf = Bytes.create bufsize in
    let ret = ref "" in
    let r = ref 1 in
    while !r <> 0 do
      r := read ssl buf 0 bufsize;
      ret := !ret ^ Bytes.sub_string buf 0 !r
    done;
    !ret

  let input_char ssl =
    let tmp = Bytes.create 1 in
    if read ssl tmp 0 1 <> 1 then raise End_of_file else Bytes.get tmp 0

  let input_int ssl =
    let i = ref 0 in
    let tmp = Bytes.create 4 in
    let read = read ssl tmp 0 4 in
    if read < 4 then failwith "input_int failed to read 4 bytes";
    i := int_of_char (Bytes.get tmp 0);
    i := (!i lsl 8) + int_of_char (Bytes.get tmp 1);
    i := (!i lsl 8) + int_of_char (Bytes.get tmp 2);
    i := (!i lsl 8) + int_of_char (Bytes.get tmp 3);
    !i
end

(* We apply the functor twice. The releasing functions are imported as
   default *)
include Make (Runtime_unlock_base)
module Runtime_lock = Make (Runtime_lock_base)

(** Deprecated functions for compatibility with older version *)
let read_into_bigarray_blocking : socket -> bigarray -> int -> int -> int =
  Runtime_lock.read_into_bigarray

let write_bigarray_blocking : socket -> bigarray -> int -> int -> int =
  Runtime_lock.write_bigarray
