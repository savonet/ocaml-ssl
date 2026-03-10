open Alcotest

let test_verify () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1342) in
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
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1343) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_host ssl "localhost";
  Unix.connect sock addr;
  Ssl.connect ssl;
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

let test_read_write () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1344) in
  Util.server_thread addr (Some (fun _ -> "received")) |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  let send_msg = "send" in
  let write_buf = Bytes.create (String.length send_msg) in
  Ssl.write ssl write_buf 0 4 |> ignore;
  let read_buf = Bytes.create 8 in
  Ssl.read ssl read_buf 0 8 |> ignore;
  Ssl.shutdown_connection ssl;
  check string "received message" "received" (Bytes.to_string read_buf)

let test_read_short_does_not_clobber_tail () =
  let iterations = 64 in
  let io_size = 4096 in
  let base_port = 20000 + (Unix.getpid () mod 10000) in
  for i = 0 to iterations - 1 do
    let port = base_port + i in
    let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", port) in
    Util.server_thread addr (Some (fun _ -> "z")) |> ignore;

    let context = Ssl.create_context TLSv1_3 Client_context in
    let ssl = Ssl.open_connection_with_context context addr in
    let write_buf = Bytes.make io_size 'x' in
    let read_buf = Bytes.make io_size '?' in
    let bytes_read =
      Ssl.write ssl write_buf 0 io_size |> ignore;
      Ssl.read ssl read_buf 0 io_size
    in
    Ssl.shutdown_connection ssl;
    check int "short read length" 1 bytes_read;
    check char "first byte copied" 'z' (Bytes.get read_buf 0);
    check
      string
      "tail preserved"
      (String.make (io_size - 1) '?')
      (Bytes.sub_string read_buf 1 (io_size - 1))
  done

let () =
  run
    "Ssl io functions"
    [ ( "IO"
      , [ test_case "Verify" `Quick test_verify
        ; test_case "Set host" `Quick test_set_host
        ; test_case "Read write" `Quick test_read_write
        ; test_case
            "Short read preserves tail"
            `Quick
            test_read_short_does_not_clobber_tail
        ] )
    ]
