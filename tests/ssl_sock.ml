open Alcotest
open Util

let test_sockets_sni () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1340) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_client_SNI_hostname ssl "localhost";
  Unix.connect sock addr;
  Ssl.connect ssl;
  Ssl.flush ssl;
  Ssl.shutdown_connection ssl;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error )

let test_sockets_alpn () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1341) in
  Util.server_thread addr None |> ignore;
  let context = Ssl.create_context TLSv1_3 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_alpn_protos ssl ["http/1.1"];
  Unix.connect sock addr;
  Ssl.connect ssl;
  let negotatiated_proto = Ssl.get_negotiated_alpn_protocol ssl in
  Ssl.flush ssl;
  Ssl.shutdown_connection ssl;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error );
  check (option string) "protocol negotiated" (Some("http/1.1")) negotatiated_proto


let () = 
  Alcotest.run "Ssl socket functions"
    [
      ( "Sockets",
        [
          test_case "Set client SNI" `Quick test_sockets_sni;
          test_case "ALPN protocols" `Quick test_sockets_alpn;
        ] );
    ]