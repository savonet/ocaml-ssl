(** Get the colon-separated hex representation of a binary string. *)
let hex_digest digest =
  let rec go acc i =
    if i < 0 then acc
    else
      let byte = Printf.sprintf "%02X" @@ int_of_char digest.[i] in
      go (byte :: acc) (i - 1)
  in
  go [] (String.length digest - 1) |> String.concat ":"

(* The reference hashes come from Firefox’ certificate viewer. It doesn’t show
 * the SHA384 hash, hence its absence from the tests. *)

let test_sha1 () =
  Alcotest.(check string)
    "same digest" "5F:B7:EE:06:33:E2:59:DB:AD:0C:4C:9A:E6:D3:8F:1A:61:C7:DC:25"
    Ssl.(
      read_certificate "digicert_certificate.pem" |> digest `SHA1 |> hex_digest)

let test_sha256 () =
  Alcotest.(check string)
    "same digest"
    "74:31:E5:F4:C3:C1:CE:46:90:77:4F:0B:61:E0:54:40:88:3B:A9:A0:1E:D0:0B:A6:AB:D7:80:6E:D3:B1:18:CF"
    Ssl.(
      read_certificate "digicert_certificate.pem"
      |> digest `SHA256
      |> hex_digest)

let () =
  let open Alcotest in
  run "Ssl"
    [
      ( "digest",
        [
          test_case "SHA1" `Quick test_sha1;
          test_case "SHA256" `Quick test_sha256;
        ] );
    ]
