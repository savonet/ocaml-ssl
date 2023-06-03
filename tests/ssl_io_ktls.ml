open Alcotest

module Util = Util_ktls

let test_verify () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 11342) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context ~ktls:true TLSv1_2 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  assert(Ssl.ktls_send_available ssl);
  assert(Ssl.ktls_recv_available ssl);
  let verify_result =
    try
      Ssl.verify ssl;
      ""
    with
    | e -> Printexc.to_string e
  in
  Ssl.shutdown_connection ssl;
  check
    bool
    "no verify errors"
    true
    (Str.search_forward
       (Str.regexp_string "error:00:000000:lib(0)")
       verify_result
       0
    > 0)

let test_set_host () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 11343) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context ~ktls:true TLSv1_2 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_host ssl "localhost";
  Unix.connect sock addr;
  Ssl.connect ssl;
  let verify_result =
    try
      Ssl.verify ssl;
      assert(Ssl.ktls_send_available ssl);
      assert(Ssl.ktls_recv_available ssl);
      ""
    with
    | e -> Printexc.to_string e
  in
  Ssl.shutdown_connection ssl;
  check
    bool
    "no verify errors"
    true
    (Str.search_forward
       (Str.regexp_string "error:00:000000:lib(0)")
       verify_result
       0
    > 0)

let test_read_write () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 11344) in
  Util.server_thread addr (Some (fun _ -> "received")) |> ignore;

  let context = Ssl.create_context ~ktls:true TLSv1_2 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  assert(Ssl.ktls_send_available ssl);
  assert(Ssl.ktls_recv_available ssl);
  let send_msg = "send" in
  let write_buf = Bytes.create (String.length send_msg) in
  Unix.single_write (Ssl.file_descr_of_socket ssl) write_buf 0 4 |> ignore;
  let read_buf = Bytes.create 8 in
  Unix.read (Ssl.file_descr_of_socket ssl) read_buf 0 8 |> ignore;
  Ssl.shutdown_connection ssl;
  check string "received message" "received" (Bytes.to_string read_buf)

let () =
  run
    "Ssl io functions"
    [ ( "IO"
      , [ test_case "Verify" `Quick test_verify
        ; test_case "Set host" `Quick test_set_host
        ; test_case "Read write" `Quick test_read_write
        ] )
    ]