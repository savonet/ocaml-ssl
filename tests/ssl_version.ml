open Alcotest
open Ssl

let test_init () = init () |> ignore

(* This test is not super robust b/c `openssl` might not be installed or
   installed but linked to a different shared libary. For this reason, this test
   is only run in our internal github action CI. *)
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
    "Ssl version"
    [ ( "Version"
      , [ test_case "Test init" `Quick test_init
        ; test_case "Test version" `Quick test_version
        ] )
    ]
