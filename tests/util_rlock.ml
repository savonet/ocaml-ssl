module Ssl = struct
  include Ssl

  let[@ocaml.alert "-deprecated"] get_error_string = get_error_string
end

open Ssl
open Ssl.Runtime_lock

type server_args =
  { address : Unix.sockaddr
  ; parser : (string -> string) option
  }

let server_rw_loop ssl parser_func =
  let rw_loop = ref true in
  while !rw_loop do
    try
      let read_buf = Bytes.create 256 in
      let read_bytes = read ssl read_buf 0 256 in
      if read_bytes > 0
      then (
        let input = Bytes.to_string read_buf in
        let response = parser_func input in
        Ssl.write_substring ssl response 0 (String.length response) |> ignore;
        Ssl.close_notify ssl |> ignore;
        rw_loop := false)
    with
    | Read_error(Error_want_read|Error_want_accept|
                 Error_want_connect|Error_want_write|Error_zero_return) ->
       ()
    | Read_error _ -> rw_loop := false
  done

let server_init args =
  try
    (* Server initialization *)
    let socket = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
    Unix.setsockopt socket Unix.SO_REUSEADDR true;
    Unix.bind socket args.address;
    let context = create_context TLSv1_3 Server_context in
    use_certificate context "server.pem" "server.key";
    Ssl.set_context_alpn_select_callback context (fun client_protos ->
        List.find_opt (fun opt -> opt = "http/1.1") client_protos);
    (* Signal ready and listen for connection *)
    Unix.listen socket 1;
    Some (socket, context)
  with
  | exn ->
    Printexc.to_string exn |> print_endline;
    None

let server_listen args =
  match server_init args with
  | None ->
    Thread.exit () [@warning "-3"]
  | Some (socket, context) ->
    let _ = Unix.select [socket] [] [] (-1.0) in
    let listen = Unix.accept socket in
    Unix.set_nonblock (fst listen);
    let ssl = embed_socket (fst listen) context in
    let rec fn () =
      try
        accept ssl;
        (* Exit right away unless we need to rw *)
        (match args.parser with
         | Some parser_func -> server_rw_loop ssl parser_func
         | None ->
            ();
            shutdown ssl;
            exit 0)
      with
        Accept_error(Error_want_read|Error_want_write
                    |Error_want_connect|Error_want_accept|Error_zero_return) ->
        fn ()
    in
    fn ()

let server_thread addr parser =
  let args = { address = addr; parser } in
  let pid = Unix.fork () in
  if pid = 0 then
    server_listen args
  else
    Unix.sleep 1; pid

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
