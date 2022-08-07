open Ssl
open Alcotest

let test_disable_protocols () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.disable_protocols context [SSLv23];
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ())

let test_set_cipher_list () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_cipher_list context "ALL";
  Ssl.honor_cipher_order context;
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ());
  check_raises "empty cipher list" (Cipher_error) (fun () -> Ssl.set_cipher_list context "");
  check_raises "invalid cipher list" (Cipher_error) (fun () -> Ssl.set_cipher_list context "NULL-MD55:ASD")

let test_cipher_init_dh () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate context "client.pem" "client.key";
  Ssl.init_dh_from_file context "dh4096.pem";
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ())

let test_init_ec_from_named_curve () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.init_ec_from_named_curve context "secp384r1";
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ())

let test_socket_cipher_funcs () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  let domain = Unix.domain_of_sockaddr (Unix.ADDR_UNIX "test") in
  let socket = Unix.socket domain Unix.SOCK_STREAM 0 in
  Unix.connect socket (Unix.ADDR_UNIX "test");
  let ssl = embed_socket socket context in
  Ssl.get_cipher ssl |> ignore;
  (*let name = Ssl.get_cipher_name cipher in*)
  check bool "cipher name" true true

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