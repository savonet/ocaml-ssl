open Ssl
open Alcotest
let test_create_context () = 
  Ssl.create_context TLSv1_3 Server_context |> ignore;
  let error = Ssl.get_error_string () in
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" error

let test_use_certificate () =
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate context "client.pem" "client.key";
  let error = Ssl.get_error_string () in
  check string "no errors" "error:00000000:lib(0):func(0):reason(0)" error

let test_use_certificate_errors () =
  let context = Ssl.create_context TLSv1_3 Server_context in

  (* Missing certificate *)
  check_raises "certificate error" (Certificate_error "error:02001002:system library:fopen:No such file or directory")  (fun () -> Ssl.use_certificate context "" "client.key")

let () =
  Alcotest.run "Ssl context"
    [
      ( "Context",
        [
          test_case "Create context" `Quick test_create_context;
          test_case "Use certificate" `Quick test_use_certificate;
          test_case "Use certificate errors" `Quick test_use_certificate_errors;
        ] );
    ]