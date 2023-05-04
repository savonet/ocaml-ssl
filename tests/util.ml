open Ssl

type server_args = {
  address: Unix.sockaddr;
  condition: Condition.t;
  mutex: Mutex.t;
  parser: (string -> string) option
  }
let server_rw_loop ssl parser_func =
  let rw_loop = ref true in
  while !rw_loop
  do
    try
      let read_buf = Bytes.create 256 in
      let read_bytes = read ssl read_buf 0 256 in
      if read_bytes > 0 then
        let input = Bytes.to_string read_buf in
        let response = (parser_func input) in
        Ssl.write_substring ssl response 0 (String.length response) |> ignore;
        Ssl.close_notify ssl |> ignore;
        rw_loop := false
    with
    | Read_error read_error ->
      match read_error with
      | Error_ssl ->
        rw_loop := false;
      | _ -> ();
  done

let server_init args =
  try
    (* Server initialization *)
    Mutex.lock args.mutex;
    let socket = Unix.socket (Unix.PF_INET) Unix.SOCK_STREAM 0 in
    Unix.setsockopt socket Unix.SO_REUSEADDR true;
    Unix.bind socket args.address;
    let context = create_context TLSv1_3 Server_context in
    use_certificate context "server.pem" "server.key";
    Ssl.set_context_alpn_select_callback context (fun client_protos ->
      List.find_opt (fun opt -> opt = "http/1.1") client_protos
    );
    (* Signal ready and listen for connection *)
    Unix.listen socket 1;
    Some (socket, context)
  with
    exn -> Printexc.to_string exn |> print_endline; None
let server_listen args =
  match server_init args with
  | None -> 
    Mutex.unlock args.mutex;
    Condition.signal args.condition;
    Thread.exit ()
  | Some (socket, context) ->
    Mutex.unlock args.mutex;
    Condition.signal args.condition;
    let listen = Unix.accept socket in
    let ssl = embed_socket (fst listen) context in
    accept ssl;
    (* Exit right away unless we need to rw *)
    match args.parser with
    | Some parser_func -> server_rw_loop ssl parser_func
    | None -> ()
    ;
    shutdown ssl;
    Thread.exit () [@warning "-3"]
let server_thread addr parser =
  let mutex = Mutex.create () in
  Mutex.lock mutex;
  let condition = Condition.create () in
  let args = { address = addr; condition = condition; mutex = mutex; parser = parser } in
  let thread = Thread.create server_listen args in
  Condition.wait condition mutex;
  thread

let check_ssl_no_error err = Str.string_partial_match (Str.regexp_string "error:00000000:lib(0)") err 0

let pp_protocol ppf = function
  | SSLv23 -> Format.fprintf ppf "SSLv23" 
  | SSLv3 -> Format.fprintf ppf "SSLv3"
  | TLSv1 -> Format.fprintf ppf "TLSv1"
  | TLSv1_1 -> Format.fprintf ppf "TLSv1_1"
  | TLSv1_2 -> Format.fprintf ppf "TLSv1_2"
  | TLSv1_3 -> Format.fprintf ppf "TLSv1_3"

let protocol_testable =
  Alcotest.testable pp_protocol (fun r1 r2 -> r1 == r2)
