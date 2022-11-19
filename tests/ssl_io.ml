open Util
open Alcotest

let test_verify () = 
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1342) in
  Util.server_thread addr |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
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
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error );
  let error_string = List.nth (Str.bounded_split (Str.regexp_string(":")) verify_result 2) 1 |> String.trim in
  check bool "no verify errors" true (error_string |> check_ssl_no_error)

let () = 
  run "Ssl io functions"
    [
      ( "IO",
        [
          test_case "Verify" `Quick test_verify;
        ] );
    ]