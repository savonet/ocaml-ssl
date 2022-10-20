open Alcotest
let test_init () = 
    Ssl.init () |> ignore

let () =
  Alcotest.run "Ssl communication"
    [
      ( "Communication",
        [
          test_case "Test init" `Quick test_init;
        ] );
    ]