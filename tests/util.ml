open Ssl

type server_args = {
  address: Unix.sockaddr;
  condition: Condition.t;
  mutex: Mutex.t
  }
let server_listen args =
  Mutex.lock args.mutex;
  init ~thread_safe: true ();
  let socket = Unix.socket (Unix.PF_INET) Unix.SOCK_STREAM 0 in
  Unix.bind socket args.address;
  Unix.listen socket 1;
  let context = create_context TLSv1_3 Server_context in
  use_certificate context "server.pem" "server.key";
  Ssl.set_context_alpn_select_callback context (fun client_protos ->
    List.find_opt (fun opt -> opt = "http/1.1") client_protos
  );
  (* End server initialization *)
  Mutex.unlock args.mutex;
  Condition.signal args.condition;
  let listen = Unix.accept socket in
  let ssl = embed_socket (fst listen) context in
  accept ssl;
  while true do
    try
      read ssl (Bytes.create 16000) 0 16000 |> ignore;
    with
    | Read_error e ->
      match e with
      | Error_zero_return -> shutdown ssl;
      | _ -> Thread.exit () [@warning "-3"];
  done
let server_thread addr =
  let mutex = Mutex.create () in
  Mutex.lock mutex;
  let condition = Condition.create () in
  let args = { address = addr; condition = condition; mutex = mutex } in
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
