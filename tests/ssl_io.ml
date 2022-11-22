open Alcotest

let cacertfile = open_in "ca.pem"
let cacertstring = really_input_string cacertfile (in_channel_length cacertfile)

let test_verify () = 
  Ssl.init ~thread_safe:true ();
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1342) in
  Util.server_thread addr |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  Ssl.add_cert_to_store context cacertstring;
  let ssl = Ssl.open_connection_with_context context addr in
  let verify_result =
    (
      try
        Ssl.verify ssl;
        ""
      with
        | e -> Printexc.to_string e
    )
  in
  Ssl.shutdown_connection ssl;
  check string "no verify errors" "" verify_result

let test_set_host () = 
  Ssl.init ~thread_safe:true ();
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1343) in
  Util.server_thread addr |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  Ssl.add_cert_to_store context cacertstring;
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_host ssl "localhost";
  Unix.connect sock addr;
  Ssl.connect ssl;
  let verify_result =
    (
      try
        Ssl.verify ssl;
        ""
      with
        | e -> Printexc.to_string e
    )
  in
  Ssl.shutdown_connection ssl;
  check string "no verify errors" "" verify_result

let () = 
  run "Ssl io functions"
    [
      ( "IO",
        [
          test_case "Verify" `Quick test_verify;
          test_case "Set host" `Quick test_set_host;
        ] );
    ]