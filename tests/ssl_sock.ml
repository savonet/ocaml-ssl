open Alcotest
open Util
let test_sockets () = 
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1339) in
  Util.server_thread addr |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = Ssl.open_connection_with_context context addr in
  Ssl.flush ssl;
  Ssl.shutdown ssl;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error )

let () = 
  Alcotest.run "Ssl socket functions"
    [
      ( "Sockets",
        [
          test_case "Socket main functions" `Quick test_sockets;
        ] );
    ]