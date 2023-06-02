open Alcotest

module Ssl = struct
  include Ssl
  include Ssl.Runtime_lock
end

module Util = Util_rlock

let test_verify () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 2342) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  let verify_result =
    try
      Ssl.verify ssl;
      ""
    with
    | e -> Printexc.to_string e
  in
  let rec fn () =
    try
      Ssl.shutdown_connection ssl;
    with
      Ssl.(Connection_error(Error_want_write|Error_want_read|
                         Error_want_accept|Error_want_connect|Error_zero_return)) ->
      fn ()
  in
  fn ();
  check
    bool
    "no verify errors"
    true
    (Str.search_forward
       (Str.regexp_string "error:00000000:lib(0)")
       verify_result
       0
    > 0)

let test_set_host () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 2343) in
  let pid = Util.server_thread addr None in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_host ssl "localhost";
  Unix.connect sock addr;
  Unix.set_nonblock sock;
  let rec fn () =
    try
      Ssl.connect ssl;
    with
      Ssl.(Connection_error(Error_want_write|Error_want_read|
                         Error_want_accept|Error_want_connect|Error_zero_return)) ->
      fn ()
  in fn ();

  let verify_result =
    try
      Ssl.verify ssl;
      ""
    with
    | e -> Printexc.to_string e
  in
  let rec fn () =
    try
      Ssl.shutdown_connection ssl;
    with
      Ssl.(Connection_error(Error_want_write|Error_want_read|
                         Error_want_accept|Error_want_connect|Error_zero_return)) ->
      fn ()
  in
  fn ();
  check
    bool
    "no verify errors"
    true
    (Str.search_forward
       (Str.regexp_string "error:00000000:lib(0)")
       verify_result
       0
     > 0);
  Unix.kill pid Sys.sigint;
  Unix.waitpid [] pid |> ignore


let test_read_write () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 2344) in
  let pid = Util.server_thread addr (Some (fun _ -> "received")) in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  Unix.set_nonblock (Ssl.file_descr_of_socket ssl);
  let send_msg = "send" in
  let write_buf = Bytes.create (String.length send_msg) in
  let rec fn () =
    try Ssl.write ssl write_buf 0 4 |> ignore;
    with Ssl.(Write_error(Error_want_write|Error_want_read|
                          Error_want_accept|Error_want_connect|Error_zero_return)) ->
      fn ()
  in fn ();
  let read_buf = Bytes.create 8 in
  let rec fn () =
    try Ssl.read ssl read_buf 0 8 |> ignore;
    with Ssl.(Read_error(Error_want_write|Error_want_read|
                          Error_want_accept|Error_want_connect|Error_zero_return)) ->
      fn ()
  in fn ();
  Ssl.shutdown_connection ssl;
  check string "received message" "received" (Bytes.to_string read_buf);
  Unix.kill pid Sys.sigint;
  Unix.waitpid [] pid |> ignore

let () =
  run
    "Ssl io functions with Ssl.Runtime_lock and non blocking socket"
    [ ( "IO"
      , [ test_case "Verify" `Quick test_verify
        ; test_case "Set host" `Quick test_set_host
        ; test_case "Read write" `Quick test_read_write
        ] )
    ]
