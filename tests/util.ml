module Ssl = struct
  include Ssl

  let[@ocaml.alert "-deprecated"] get_error_string = get_error_string
end

open Ssl

let server_rw_loop ssl parser_func =
  let rw_loop = ref true in
  while !rw_loop do
    try
      let read_buf = Bytes.create 256 in
      let read_bytes = read ssl read_buf 0 256 in
      if read_bytes > 0 then (
        let input = Bytes.to_string read_buf in
        let response = parser_func input in
        Ssl.write_substring ssl response 0 (String.length response) |> ignore;
        Ssl.close_notify ssl |> ignore;
        rw_loop := false)
    with Read_error read_error -> (
      match read_error with Error_ssl -> rw_loop := false | _ -> ())
  done

(* Listens on an ephemeral loopback port and serves one connection in a
   thread, returning the address to connect to. *)
let server_thread parser =
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind socket (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  Unix.listen socket 1;
  let context = create_context TLSv1_3 Server_context in
  use_certificate context "server.pem" "server.key";
  Ssl.set_context_alpn_select_callback context (fun client_protos ->
      List.find_opt (fun opt -> opt = "http/1.1") client_protos);
  let serve () =
    let client, _ = Unix.accept socket in
    Unix.close socket;
    let ssl = embed_socket client context in
    accept ssl;
    match parser with
      | Some parser_func -> server_rw_loop ssl parser_func
      | None -> shutdown ssl
  in
  ignore (Thread.create serve ());
  Unix.getsockname socket

let check_ssl_no_error err =
  Str.string_partial_match (Str.regexp_string "error:00000000:lib(0)") err 0

let[@ocaml.alert "-deprecated"] pp_protocol ppf = function
  | SSLv23 -> Format.fprintf ppf "SSLv23"
  | SSLv3 -> Format.fprintf ppf "SSLv3"
  | TLSv1 -> Format.fprintf ppf "TLSv1"
  | TLSv1_1 -> Format.fprintf ppf "TLSv1_1"
  | TLSv1_2 -> Format.fprintf ppf "TLSv1_2"
  | TLSv1_3 -> Format.fprintf ppf "TLSv1_3"

let protocol_testable = Alcotest.testable pp_protocol (fun r1 r2 -> r1 == r2)
