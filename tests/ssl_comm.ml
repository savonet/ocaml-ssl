open Alcotest
open Ssl

let test_init () = init () |> ignore

let test_error_queue () =
  let context = Ssl.create_context TLSv1_3 Client_context in
  try use_certificate context "expired.pem" "" with
  | _ ->
    ();
    let err = Error.peek_error () in
    check int "Error code" 32 err.library_number;
    check string "Library string" "BIO routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason);
    let err = Error.peek_last_error () in
    check int "Error code" 20 err.library_number;
    check string "Library string" "SSL routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason);
    let err = Error.get_error () in
    check int "Error code" 32 err.library_number;
    check string "Library string" "BIO routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason);
    let err = Error.get_error () in
    check int "Error code" 20 err.library_number;
    check string "Library string" "SSL routines" (Option.get err.lib);
    check string "Reason string" "system lib" (Option.get err.reason)

let test_version () =
  let ch = Unix.open_process_in "openssl version" in
  let m, n, p =
    Scanf.(bscanf (Scanning.from_channel ch)) "OpenSSL %d.%d.%d" (fun x y z ->
        x, y, z)
  in
  Unix.close_process_in ch |> ignore;
  check int "major" m Ssl.native_library_version.major;
  check int "minor" n Ssl.native_library_version.minor;
  check int "patch" p Ssl.native_library_version.patch

let () =
  Alcotest.run
    "Ssl communication"
    [ ( "Communication"
      , [ test_case "Test init" `Quick test_init
        ; test_case "Test version" `Quick test_version
        ; test_case "Test error queue" `Quick test_error_queue
        ] )
    ]
