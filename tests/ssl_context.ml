open Ssl
open Alcotest

let certfile = open_in "client.pem"
let certstring = really_input_string certfile (in_channel_length certfile)
let clientkeyfile = open_in "client.key"
let clientkeystring = really_input_string clientkeyfile (in_channel_length clientkeyfile)
let serverkeyfile = open_in "server.key"
let serverkeystring = really_input_string serverkeyfile (in_channel_length serverkeyfile)

let test_create_context () = 
  Ssl.create_context TLSv1_3 Server_context |> ignore;
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ())

let test_add_extra_chain_cert () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.add_extra_chain_cert context certstring;
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ());
  check_raises "certificate error" (Certificate_error "error:0909006C:PEM routines:get_name:no start line") (fun () -> Ssl.add_extra_chain_cert context "")

let test_add_cert_to_store () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.add_cert_to_store context certstring;
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ());
  check_raises "certificate error" (Certificate_error "error:0909006C:PEM routines:get_name:no start line") (fun () -> Ssl.add_cert_to_store context "")

let test_use_certificate () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate context "client.pem" "client.key";
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ());
  check_raises "certificate error" (Certificate_error "error:02001002:system library:fopen:No such file or directory")  (fun () -> Ssl.use_certificate context "" "client.key");
  check_raises "key error" (Private_key_error "error:02001002:system library:fopen:No such file or directory") (fun () -> Ssl.use_certificate context "client.pem" "");
  check_raises "unmatching key" (Private_key_error "error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch") (fun () -> Ssl.use_certificate context "client.pem" "server.key")

let test_use_certificate_from_string () = 
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate_from_string context certstring clientkeystring;
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ());
  check_raises "certificate error" (Certificate_error "error:0909006C:PEM routines:get_name:no start line") (fun () -> Ssl.use_certificate_from_string context "" clientkeystring);
  check_raises "key error" (Private_key_error "error:0909006C:PEM routines:get_name:no start line") (fun () -> Ssl.use_certificate_from_string context certstring "");
  check_raises "unmatching key" (Private_key_error "error:0B080074:x509 certificate routines:X509_check_private_key:key values mismatch") (fun () -> Ssl.use_certificate_from_string context certstring serverkeystring)

let test_set_password_callback () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_password_callback context (fun _ -> "password");
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ())

let test_set_client_CA_list_from_file () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_client_CA_list_from_file context "ca.pem";
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ());
  check_raises "certificate error" (Certificate_error "error:02001002:system library:fopen:No such file or directory") (fun () -> Ssl.set_client_CA_list_from_file context "")

let test_set_client_verify_callback () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_verify_depth context (1);
  Ssl.use_certificate context "client.pem" "client.key";
  Ssl.set_client_verify_callback_verbose true;
  Ssl.set_verify context [Verify_peer] (Some Ssl.client_verify_callback);
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ());
  check_raises "verify depth error" (Invalid_argument "depth") (fun () -> Ssl.set_verify_depth context (-1))

let test_context_alpn () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_context_alpn_protos context ["http/1.1"];
  Ssl.set_context_alpn_select_callback context (fun _ -> Some "http/1.1");
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" (Ssl.get_error_string ())

let () =
  Alcotest.run "Ssl context"
    [
      ( "Context",
        [
          test_case "Create context" `Quick test_create_context;
          test_case "Add extra chain cert" `Quick test_add_extra_chain_cert;
          test_case "Add cert to store" `Quick test_add_cert_to_store;
          test_case "Use certificate" `Quick test_use_certificate;
          test_case "Use certificate from string" `Quick test_use_certificate_from_string;
          test_case "Set password callback" `Quick test_set_password_callback;
          test_case "Set client CA list from file" `Quick test_set_client_CA_list_from_file;
          test_case "Set verify functions" `Quick test_set_client_verify_callback;
          test_case "Context alpn" `Quick test_context_alpn;
        ] );
    ]