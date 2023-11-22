open Alcotest
open Util


let test_crl_no_crl () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1345) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let set_default = Ssl.set_default_verify_paths context in
  Ssl.set_flags context [Ssl.X509_v_flag_crl_check ; Ssl.X509_v_flag_crl_check_all ];
  Ssl.load_verify_locations context "ca.pem" "";
  let ssl = Ssl.open_connection_with_context context addr in
  let cert = Ssl.get_certificate ssl in
  let subject = Ssl.get_subject cert in
  let verify_result = Ssl.get_verify_result ssl in
  let error_string = Ssl.get_verify_error_string 0 in

  Ssl.shutdown_connection ssl;
  check bool "set default succeded" true set_default;
  check
    string
    "check certificate"
    "/C=US/ST=California/L=San Francisco/O=Ocaml-ssl-server/CN=localhost"
    subject;
  check int "check verify result" 3 verify_result;
  check string "check error string" "ok" error_string

let test_crl_expired () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1346) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let set_default = Ssl.set_default_verify_paths context in
  Ssl.set_flags context [Ssl.X509_v_flag_crl_check ; Ssl.X509_v_flag_crl_check_all];
  Ssl.load_verify_locations context "ca.pem" "";
  let crlfile = open_in "ca_expired.crl" in
  let crlstring = really_input_string crlfile (in_channel_length crlfile) in
  Ssl.add_crl_to_store context crlstring;
  let ssl = Ssl.open_connection_with_context context addr in
  let cert = Ssl.get_certificate ssl in
  let subject = Ssl.get_subject cert in
  let verify_result = Ssl.get_verify_result ssl in
  let error_string = Ssl.get_verify_error_string 0 in

  Ssl.shutdown_connection ssl;
  check bool "set default succeded" true set_default;
  check
    string
    "check certificate"
    "/C=US/ST=California/L=San Francisco/O=Ocaml-ssl-server/CN=localhost"
    subject;
  check int "check verify result" 12 verify_result;
  check string "check error string" "ok" error_string

let test_crl_valid () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1347) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let set_default = Ssl.set_default_verify_paths context in
  Ssl.set_flags context [Ssl.X509_v_flag_crl_check ; Ssl.X509_v_flag_crl_check_all ];
  Ssl.load_verify_locations context "ca.pem" "";
  let crlfile = open_in "ca.crl" in
  let crlstring = really_input_string crlfile (in_channel_length crlfile) in
  Ssl.add_crl_to_store context crlstring;
  let ssl = Ssl.open_connection_with_context context addr in
  let cert = Ssl.get_certificate ssl in
  let subject = Ssl.get_subject cert in
  let verify_result = Ssl.get_verify_result ssl in
  let error_string = Ssl.get_verify_error_string 0 in

  Ssl.shutdown_connection ssl;
  check bool "set default succeded" true set_default;
  check
    string
    "check certificate"
    "/C=US/ST=California/L=San Francisco/O=Ocaml-ssl-server/CN=localhost"
    subject;
  check int "check verify result" 0 verify_result;
  check string "check error string" "ok" error_string

let test_crl_revoked () =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "127.0.0.1", 1348) in
  Util.server_thread addr None |> ignore;

  let context = Ssl.create_context TLSv1_3 Client_context in
  let set_default = Ssl.set_default_verify_paths context in
  Ssl.set_flags context [Ssl.X509_v_flag_crl_check ; Ssl.X509_v_flag_crl_check_all ];
  let crlfile = open_in "ca_after_revoke.crl" in
  let crlstring = really_input_string crlfile (in_channel_length crlfile) in
  Ssl.add_crl_to_store context crlstring;
  let ssl = Ssl.open_connection_with_context context addr in
  let cert = Ssl.get_certificate ssl in
  let subject = Ssl.get_subject cert in
  let verify_result = Ssl.get_verify_result ssl in
  let error_string = Ssl.get_verify_error_string 0 in

  Ssl.shutdown_connection ssl;
  check bool "set default succeded" true set_default;
  check
    string
    "check certificate"
    "/C=US/ST=California/L=San Francisco/O=Ocaml-ssl-server/CN=localhost"
    subject;
  check int "check verify result" 20 verify_result;
  check string "check error string" "ok" error_string


let () =
  Alcotest.run
    "Ssl CRL functions"
    [ ( "CRLs"
      , [
          test_case "No CRL provided" `Quick test_crl_no_crl
        ; test_case "CRL expired" `Quick test_crl_expired
        ; test_case "CRL valid and certificate valid" `Quick test_crl_valid
        ; test_case "Certificate revoked" `Quick test_crl_revoked
        ] )
    ]
