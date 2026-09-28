open Ssl
open Alcotest
open Util

let certfile = open_in "client.pem"
let certstring = really_input_string certfile (in_channel_length certfile)
let clientkeyfile = open_in "client.key"

let clientkeystring =
  really_input_string clientkeyfile (in_channel_length clientkeyfile)

let serverkeyfile = open_in "server.key"

let serverkeystring =
  really_input_string serverkeyfile (in_channel_length serverkeyfile)

let test_create_context () =
  Ssl.create_context TLSv1_3 Server_context |> ignore;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error)

let test_add_extra_chain_cert () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.add_extra_chain_cert context certstring;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  check_raises "certificate error" (Certificate_error "") (fun () ->
      try Ssl.add_extra_chain_cert context ""
      with Certificate_error _ -> raise (Certificate_error ""))

let test_add_cert_to_store () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.add_cert_to_store context certstring;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  check_raises "certificate error" (Certificate_error "") (fun () ->
      try Ssl.add_cert_to_store context ""
      with Certificate_error _ -> raise (Certificate_error ""))

let test_use_certificate () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate context "client.pem" "client.key";
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  check_raises "certificate error" (Certificate_error "") (fun () ->
      try Ssl.use_certificate context "" "client.key"
      with Certificate_error _ -> raise (Certificate_error ""));
  check_raises "key error" (Private_key_error "") (fun () ->
      try Ssl.use_certificate context "client.pem" ""
      with Private_key_error _ -> raise (Private_key_error ""));
  check_raises "unmatching key" (Private_key_error "") (fun () ->
      try Ssl.use_certificate context "client.pem" "server.key"
      with Private_key_error _ -> raise (Private_key_error ""))

let rec clear_error_queue () =
  let error = Ssl.Error.get_error () in
  if error.library_number <> 0 || error.reason_code <> 0 then
    clear_error_queue ()

let test_password_callback () =
  let encrypted_key =
    In_channel.with_open_bin "client-encrypted.key" In_channel.input_all
  in
  let loaders =
    [
      ( "file",
        fun context ->
          Ssl.use_certificate context "client.pem" "client-encrypted.key" );
      ( "string",
        fun context ->
          Ssl.use_certificate_from_string context certstring encrypted_key );
    ]
  in
  List.iter
    (fun (loader_name, load) ->
      let use_encrypted_key password =
        let context = Ssl.create_context TLSv1_3 Server_context in
        Ssl.set_password_callback context password;
        let result =
          match load context with
            | () -> "loaded"
            | exception Private_key_error _ -> "private key error"
            | exception exn -> Printexc.to_string exn
        in
        clear_error_queue ();
        result
      in
      let check_loader name expected password =
        check string
          (loader_name ^ ": " ^ name)
          expected
          (use_encrypted_key password)
      in
      check_loader "right password" "loaded" (fun _ -> "password");
      check_loader "wrong password" "private key error" (fun _ -> "wrong");
      check_loader "callback raises" "private key error" (fun _ -> raise Exit);
      check_loader "password too long" "private key error" (fun _ ->
          String.make 100_000 'a'))
    loaders

let released_callbacks = ref 0

let tracked_callback result =
  let marker = ref () in
  Gc.finalise (fun _ -> incr released_callbacks) marker;
  fun _ ->
    ignore (Sys.opaque_identity marker);
    result

let[@inline never] set_callbacks_on_dropped_context () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_password_callback context (tracked_callback "password");
  Ssl.set_password_callback context (tracked_callback "password");
  Ssl.set_context_alpn_select_callback context (tracked_callback None)

let test_callbacks_released () =
  set_callbacks_on_dropped_context ();
  for _ = 1 to 3 do
    Gc.full_major ()
  done;
  check int "released callbacks" 3 !released_callbacks

let test_use_certificate_from_string () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate_from_string context certstring clientkeystring;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  check_raises "certificate error" (Certificate_error "") (fun () ->
      try Ssl.use_certificate_from_string context "" clientkeystring
      with Certificate_error _ -> raise (Certificate_error ""));
  check_raises "key error" (Private_key_error "") (fun () ->
      try Ssl.use_certificate_from_string context certstring ""
      with Private_key_error _ -> raise (Private_key_error ""));
  check_raises "unmatching key" (Private_key_error "") (fun () ->
      try Ssl.use_certificate_from_string context certstring serverkeystring
      with Private_key_error _ -> raise (Private_key_error ""))

let test_set_password_callback () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_password_callback context (fun _ -> "password");
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error)

let test_set_client_CA_list_from_file () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_client_CA_list_from_file context "ca.pem";
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  check_raises "certificate error" (Certificate_error "") (fun () ->
      try Ssl.set_client_CA_list_from_file context ""
      with Certificate_error _ -> raise (Certificate_error ""))

let test_set_client_verify_callback () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_verify_depth context 1;
  Ssl.use_certificate context "client.pem" "client.key";
  Ssl.set_client_verify_callback_verbose true;
  Ssl.set_verify context [Verify_peer] (Some Ssl.client_verify_callback);
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  check_raises "verify depth error" (Invalid_argument "depth") (fun () ->
      Ssl.set_verify_depth context (-1))

let test_context_alpn () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.set_context_alpn_protos context ["http/1.1"];
  Ssl.set_context_alpn_select_callback context (fun _ -> Some "http/1.1");
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error)

let test_set_version () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  let[@alert "-deprecated"] tlsv1 = TLSv1 in
  Ssl.set_min_protocol_version context tlsv1;
  check protocol_testable "min version" tlsv1
    (Ssl.get_min_protocol_version context);
  check protocol_testable "max version" TLSv1_3
    (Ssl.get_max_protocol_version context);
  (* Set max *)
  Ssl.set_max_protocol_version context TLSv1_2;
  check protocol_testable "max version" TLSv1_2
    (Ssl.get_max_protocol_version context)

let () =
  Alcotest.run "Ssl context"
    [
      ( "Context",
        [
          test_case "Create context" `Quick test_create_context;
          test_case "Add extra chain cert" `Quick test_add_extra_chain_cert;
          test_case "Add cert to store" `Quick test_add_cert_to_store;
          test_case "Use certificate" `Quick test_use_certificate;
          test_case "Password callback" `Quick test_password_callback;
          test_case "Callbacks released" `Quick test_callbacks_released;
          test_case "Use certificate from string" `Quick
            test_use_certificate_from_string;
          test_case "Set password callback" `Quick test_set_password_callback;
          test_case "Set client CA list from file" `Quick
            test_set_client_CA_list_from_file;
          test_case "Set verify functions" `Quick
            test_set_client_verify_callback;
          test_case "Context alpn" `Quick test_context_alpn;
          test_case "Set min / max protocol version" `Quick test_set_version;
        ] );
    ]
