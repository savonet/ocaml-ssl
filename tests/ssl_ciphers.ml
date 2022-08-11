open Ssl
open Alcotest

let pp_protocol ppf = function
  | SSLv23 -> Format.fprintf ppf "SSLv23" 
  | SSLv3 -> Format.fprintf ppf "SSLv3"
  | TLSv1 -> Format.fprintf ppf "TLSv1"
  | TLSv1_1 -> Format.fprintf ppf "TLSv1_1"
  | TLSv1_2 -> Format.fprintf ppf "TLSv1_2"
  | TLSv1_3 -> Format.fprintf ppf "TLSv1_3"

let protocol_testable =
  Alcotest.testable pp_protocol (fun r1 r2 -> r1 == r2)

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
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1337) in
  Test_server.server_thread addr |> ignore;
 
  let context = Ssl.create_context TLSv1_3 Client_context in
  let ssl = open_connection_with_context context addr in
  let cipher = Ssl.get_cipher ssl in
  let name = Ssl.get_cipher_name cipher in
  let description = Ssl.get_cipher_description cipher in
  let version = Ssl.get_cipher_version cipher in
  let socket_version = Ssl.version ssl in
  check string "cipher name" "TLS_AES_256_GCM_SHA384" name;
  check string "cipher description" "TLS_AES_256_GCM_SHA384  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(256) Mac=AEAD\n" description;
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