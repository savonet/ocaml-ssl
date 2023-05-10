open Ssl
let server_listen args =
  let (sockaddr, condition, mutex) = args in
  Mutex.lock mutex;
  Ssl.init ();
  let socket = Unix.socket (Unix.PF_INET) Unix.SOCK_STREAM 0 in
  Unix.bind socket sockaddr;
  Unix.listen socket 1;
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate context "ca.pem" "ca.key";
  Mutex.unlock mutex;
  Condition.signal condition;
  let listen = Unix.accept socket in
  let ssl = Ssl.embed_socket (fst listen) context in
  Ssl.accept ssl;
  while true do
    try
      Ssl.read ssl (Bytes.create 16000) 0 16000 |> ignore;
    with
    | Read_error e ->
      match e with
      | Error_zero_return -> Ssl.shutdown ssl;
      | _ -> Thread.exit () [@warning "-3"];
  done
let server_thread addr =
  let mutex = Mutex.create () in
  Mutex.lock mutex;
  let condition = Condition.create () in
  let thread = Thread.create server_listen (addr, condition, mutex) in
  Condition.wait condition mutex;
  thread

let check_ssl_no_error err = Str.string_partial_match (Str.regexp_string "error:00000000:lib(0)") err 0

let pp_protocol ppf = function
  | SSLv23                  -> Format.fprintf ppf "SSLv23"
  | SSLv3                   -> Format.fprintf ppf "SSLv3"
  | TLSv1   [@warning "-3"] -> Format.fprintf ppf "TLSv1"
  | TLSv1_1 [@warning "-3"] -> Format.fprintf ppf "TLSv1_1"
  | TLSv1_2 [@warning "-3"] -> Format.fprintf ppf "TLSv1_2"
  | TLSv1_3                 -> Format.fprintf ppf "TLSv1_3"

let protocol_testable =
  Alcotest.testable pp_protocol (fun r1 r2 -> r1 == r2)
