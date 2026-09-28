open Alcotest

let test_verify () =
  let addr = Util.server_thread None in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  let verify_result =
    try
      Ssl.verify ssl;
      ""
    with e -> Printexc.to_string e
  in
  Ssl.shutdown_connection ssl;
  check bool "no verify errors" true
    (Str.search_forward
       (Str.regexp_string "error:00:000000:lib(0)")
       verify_result 0
    > 0)

let test_set_host () =
  let addr = Util.server_thread None in

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
    with e -> Printexc.to_string e
  in
  Ssl.shutdown_connection ssl;
  check bool "no verify errors" true
    (Str.search_forward
       (Str.regexp_string "error:00:000000:lib(0)")
       verify_result 0
    > 0)

let test_reject_invalid_names () =
  let context = Ssl.create_context TLSv1_3 Client_context in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  let rejects name f =
    match f () with
      | () -> fail (name ^ " was accepted")
      | exception Invalid_argument _ -> ()
  in
  rejects "set_ip with a hostname" (fun () -> Ssl.set_ip ssl "localhost");
  rejects "set_host with a NUL byte" (fun () ->
      Ssl.set_host ssl "evil.com\000.good.com");
  rejects "SNI hostname with a NUL byte" (fun () ->
      Ssl.set_client_SNI_hostname ssl "evil.com\000.good.com");
  Ssl.set_ip ssl "127.0.0.1";
  Ssl.set_host ssl "localhost";
  Unix.close sock

let test_bounds () =
  let context = Ssl.create_context TLSv1_3 Client_context in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  let bytes = Bytes.create 8 in
  let bigarray = Bigarray.(Array1.create char c_layout 8) in
  let functions =
    [
      ("read", fun start length -> Ssl.read ssl bytes start length);
      ("write", fun start length -> Ssl.write ssl bytes start length);
      ( "write_substring",
        fun start length ->
          Ssl.write_substring ssl (Bytes.to_string bytes) start length );
      ( "read_into_bigarray",
        fun start length -> Ssl.read_into_bigarray ssl bigarray start length );
      ( "write_bigarray",
        fun start length -> Ssl.write_bigarray ssl bigarray start length );
      ( "Runtime_lock.read",
        fun start length -> Ssl.Runtime_lock.read ssl bytes start length );
      ( "Runtime_lock.write",
        fun start length -> Ssl.Runtime_lock.write ssl bytes start length );
      ( "Runtime_lock.read_into_bigarray",
        fun start length ->
          Ssl.Runtime_lock.read_into_bigarray ssl bigarray start length );
      ( "Runtime_lock.write_bigarray",
        fun start length ->
          Ssl.Runtime_lock.write_bigarray ssl bigarray start length );
    ]
  in
  let out_of_bounds =
    [(max_int, 1); (1, max_int); (1 lsl 32, 1); (-1, 1); (0, -1); (4, 5)]
  in
  List.iter
    (fun (name, f) ->
      List.iter
        (fun (start, length) ->
          match f start length with
            | _ -> failf "%s %d %d was accepted" name start length
            | exception Invalid_argument _ -> ())
        out_of_bounds)
    functions;
  Unix.close sock

let test_read_write () =
  let addr = Util.server_thread (Some (fun _ -> "received")) in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  let send_msg = "send" in
  let write_buf = Bytes.create (String.length send_msg) in
  Ssl.write ssl write_buf 0 4 |> ignore;
  let read_buf = Bytes.create 8 in
  Ssl.read ssl read_buf 0 8 |> ignore;
  Ssl.shutdown_connection ssl;
  check string "received message" "received" (Bytes.to_string read_buf)

let test_input_string () =
  let addr = Util.server_thread (Some (fun _ -> "received")) in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  Ssl.output_string ssl "send";
  let received = Ssl.input_string ssl in
  Ssl.shutdown_connection ssl;
  check string "received message" "received" received

let test_read_short_does_not_clobber_tail () =
  let iterations = 64 in
  let io_size = 4096 in
  for _ = 1 to iterations do
    let addr = Util.server_thread (Some (fun _ -> "z")) in

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
    check string "tail preserved"
      (String.make (io_size - 1) '?')
      (Bytes.sub_string read_buf 1 (io_size - 1))
  done

let () =
  run "Ssl io functions"
    [
      ( "IO",
        [
          test_case "Verify" `Quick test_verify;
          test_case "Set host" `Quick test_set_host;
          test_case "Reject invalid names" `Quick test_reject_invalid_names;
          test_case "Read write" `Quick test_read_write;
          test_case "Bounds" `Quick test_bounds;
          test_case "Input string" `Quick test_input_string;
          test_case "Short read preserves tail" `Quick
            test_read_short_does_not_clobber_tail;
        ] );
    ]
