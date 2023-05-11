open Alcotest
open Util

let test_read_cert () =
  let cert = Ssl.read_certificate "client.pem" in
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error );
  let issuer = Ssl.get_issuer cert in
  let subject = Ssl.get_subject cert in
  let start_date = Ssl.get_start_date cert in
  let expiration_date = Ssl.get_expiration_date cert in
  let digest = Ssl.digest `SHA1 cert in
  check string "read issuer" "/C=US/ST=California/L=San Francisco/O=Piaf/CN=CA" issuer;
  check string "read subject" "/C=US/ST=California/L=San Francisco/O=Ocaml-ssl/CN=localhost" subject;
  check int "read start date" 26 start_date.tm_mday;
  check int "read expiration date" 23 expiration_date.tm_mday;
  check string "read digest" "_m\228R\240\250\023\253\1927\146CP(W'\238z\2489" digest

let test_cert_connection () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1338) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let set_default = Ssl.set_default_verify_paths context in
  Ssl.load_verify_locations context "ca.pem" "";
  let ssl = Ssl.open_connection_with_context context addr in
  let cert = Ssl.get_certificate ssl in
  let subject = Ssl.get_subject cert in
  let verify_result = Ssl.get_verify_result ssl in
  let error_string = Ssl.get_verify_error_string 0 in
  Ssl.shutdown_connection ssl;
  check bool "set default succeded" true set_default;
  check string "check certificate" "/C=US/ST=California/L=San Francisco/O=Ocaml-ssl-server/CN=localhost" subject;
  check int "check verify result" 0 verify_result;
  check string "check error string" "ok" error_string

let () =
  Alcotest.run "Ssl certificate functions"
    [
      ( "Certificates",
        [
          test_case "Read certificate functions" `Quick test_read_cert;
          test_case "Certificate on connection" `Quick test_cert_connection;
        ] );
    ]
