open Alcotest
open Ssl
let test_init () =
    init () |> ignore

let test_error_queue () =
  let context = Ssl.create_context TLSv1_3 Client_context in
  try use_certificate context "expired.pem" "" with | _ -> ();
  let code, lib, reason = peek_error () in
  check int "Error code" 268959746 code;
  check string "Library string" "BIO routines" lib;
  check string "Reason string" "system lib" reason;
  let code, lib, reason = peek_last_error () in
  check int "Error code" 168296450 code;
  check string "Library string" "SSL routines" lib;
  check string "Reason string" "system lib" reason;
  let code, lib, reason = get_error () in
  check int "Error code" 268959746 code;
  check string "Library string" "BIO routines" lib;
  check string "Reason string" "system lib" reason;
  let code, lib, reason = get_error () in
  check int "Error code" 168296450 code;
  check string "Library string" "SSL routines" lib;
  check string "Reason string" "system lib" reason

let () =
  Alcotest.run "Ssl communication"
    [
      ( "Communication",
        [
          test_case "Test init" `Quick test_init;
          test_case "Test peek_error_last" `Quick test_error_queue;
        ] );
    ]