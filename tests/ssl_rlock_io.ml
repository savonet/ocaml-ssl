open Alcotest

module Util = Util_rlock

module Ssl = struct
  include Ssl
  include Ssl.Runtime_lock

  let open_connection_with_context context sockaddr =
    let domain = Unix.domain_of_sockaddr sockaddr in
    let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
    try
      Unix.connect sock sockaddr;
      Unix.set_nonblock sock;
      let ssl = embed_socket sock context in
      Util.loop (fun () -> connect ssl);
      ssl
    with
    | exn ->
      Unix.close sock;
      raise exn


end

let test_verify () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 2342) in
  Util.server_thread addr None |> ignore;
  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Util.loop (fun _ -> Ssl.open_connection_with_context context addr) in
  let verify_result =
    try
      Util.loop (fun () -> Ssl.verify ssl; "")
    with
    | e -> Printexc.to_string e
  in
  Util.loop (fun () -> Ssl.shutdown_connection ssl);
  check
    bool
    "no verify errors"
    true
    (Str.search_forward
       (Str.regexp_string "error:00:000000:lib(0)::reason(0)")
       verify_result
       0
    > 0)

let test_set_host () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 2343) in
  let _ = Util.server_thread addr None in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_host ssl "localhost";
  Unix.connect sock addr;
  Unix.set_nonblock sock;
  Util.loop (fun () -> Ssl.connect ssl);
  let verify_result =
    try
      Util.loop (fun () -> Ssl.verify ssl; "");
    with
    | e -> Printexc.to_string e
  in
  Util.loop (fun () -> Ssl.shutdown_connection ssl);
  check
    bool
    "no verify errors"
    true
    (Str.search_forward
       (Str.regexp_string "error:00:000000:lib(0)::reason(0)")
       verify_result
       0
     > 0)

let test_read_write () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 2344) in
  let _ = Util.server_thread addr (Some (fun _ -> "received")) in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  let send_msg = "send" in
  let write_buf = Bytes.create (String.length send_msg) in
  Util.loop (fun () -> Ssl.write ssl write_buf 0 4 |> ignore);
  let read_buf = Bytes.create 8 in
  Util.loop (fun () -> Ssl.read ssl read_buf 0 8 |> ignore);
  Util.loop (fun () -> Ssl.shutdown_connection ssl);
  check string "received message" "received" (Bytes.to_string read_buf)

let () =
  run
    "Ssl io functions with Ssl.Runtime_lock and non blocking socket"
    [ ( "IO"
      , [ test_case "Verify" `Quick test_verify
        ; test_case "Set host" `Quick test_set_host
        ; test_case "Read write" `Quick test_read_write
        ] )
    ]
