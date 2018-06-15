
let test_client proto_list =
  Ssl.init ();
  let ctx = Ssl.create_context Ssl.TLSv1_2 Ssl.Client_context in
  Ssl.set_context_alpn_protos ctx proto_list;
  let sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string "127.0.0.1", 4433) in
  let ssl = Ssl.open_connection_with_context ctx sockaddr in
  let () =
    match Ssl.get_negotiated_alpn_protocol ssl with
    | None -> print_endline "No protocol selected"
    | Some proto -> print_endline ("Selected protocol: " ^ proto)
  in
  Ssl.shutdown ssl
