open Ssl
open Alcotest
open Util
let test_disable_protocols () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.disable_protocols context [SSLv23];
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error )

let test_set_cipher_list () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_cipher_list context "ALL";
  Ssl.honor_cipher_order context;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error );
  check_raises "empty cipher list" (Cipher_error) (fun () -> Ssl.set_cipher_list context "");
  check_raises "invalid cipher list" (Cipher_error) (fun () -> Ssl.set_cipher_list context "NULL-MD55:ASD")

let test_cipher_init_dh () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate context "client.pem" "client.key";
  Ssl.init_dh_from_file context "dh4096.pem";
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error )

let test_init_ec_from_named_curve () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.init_ec_from_named_curve context "secp384r1";
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error )

let test_socket_cipher_funcs () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1337) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = open_connection_with_context context addr in
  let cipher = Ssl.get_cipher ssl in
  let name = Ssl.get_cipher_name cipher in
  let description = Ssl.get_cipher_description cipher in
  let version = Ssl.get_cipher_version cipher in
  let socket_version = Ssl.version ssl in
  Ssl.shutdown_connection ssl;
  check string "cipher name" "TLS_AES_256_GCM_SHA384" name;
  check bool "cipher description" true (Str.string_partial_match (Str.regexp ".*Enc=AESGCM(256).*") description 0);
  check string "cipher version" "TLSv1.3" version;
  check protocol_testable "socket version"  TLSv1_3 socket_version

let () =
Alcotest.run "Ssl cipher functions"
  [
    ( "Ciphers",
      [
        test_case "Disable protocols" `Quick test_disable_protocols;
        test_case "Set cipher list" `Quick test_set_cipher_list;
        test_case "Init DH params" `Quick test_cipher_init_dh;
        test_case "Init EC params" `Quick test_init_ec_from_named_curve;
        test_case "Cipher funcs" `Quick test_socket_cipher_funcs;
      ] );
  ]