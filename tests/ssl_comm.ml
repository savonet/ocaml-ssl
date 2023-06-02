open Alcotest
open Ssl

let test_init () = init () |> ignore

let test_error_queue () =
  let context = Ssl.create_context TLSv1_3 Client_context in
  try use_certificate context "expired.pem" "" with
  | _ ->
    ();
    let err = Error.peek_error () in
    check int "Error code" 268959746 err.code;
    check string "Library string" "BIO routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason);
    let err = Error.peek_last_error () in
    check int "Error code" 168296450 err.code;
    check string "Library string" "SSL routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason);
    let err = Error.get_error () in
    check int "Error code" 268959746 err.code;
    check string "Library string" "BIO routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason);
    let err = Error.get_error () in
    check int "Error code" 168296450 err.code;
    check string "Library string" "SSL routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason)

let () =
  Alcotest.run
    "Ssl communication"
    [ ( "Communication"
      , [ test_case "Test init" `Quick test_init
        ; test_case "Test error queue" `Quick test_error_queue
        ] )
    ]
