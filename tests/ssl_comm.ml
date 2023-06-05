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
  let (m,n,p) = Scanf.scanf "OpenSSL %d.%d.%d" (fun x -> x) in
  Unix.close_process_in ch;
  check int m Ssl.ssl_version.major;
  check int n Ssl.ssl_version.minor;
  check int p Ssl.ssl_version.patch

let () =
  Alcotest.run
    "Ssl communication"
    [ ( "Communication"
      , [ test_case "Test init" `Quick test_init
        ; test_case "Test error queue" `Quick test_error_queue
        ] )
    ]
