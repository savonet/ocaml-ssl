let test_init () = 
    Ssl.(init () |> ignore)

let () =
  let open Alcotest in
  run "Ssl"
    [
      ( "Init",
        [
          test_case "Test init" `Quick test_init;
        ] );
    ]