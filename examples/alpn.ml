
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


let test_server proto_list =
  let certfile = "/Users/bobbypriambodo/Projects/forks/ocaml-tls/certificates/server.pem" in
  let privkey = "/Users/bobbypriambodo/Projects/forks/ocaml-tls/certificates/server.key" in
  let log s =
    Printf.printf "[II] %s\n%!" s
  in
  Ssl.init ();
  let sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string "127.0.0.1", 4433) in
  let domain =
    begin match sockaddr with
    | Unix.ADDR_UNIX _ -> Unix.PF_UNIX
    | Unix.ADDR_INET (_, _) -> Unix.PF_INET
    end
  in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ctx = Ssl.create_context Ssl.TLSv1_2 Ssl.Server_context in
  Ssl.use_certificate ctx certfile privkey;
  Ssl.set_context_alpn_select_callback ctx (fun client_protos ->
      log "entering callback";
      log (Printf.sprintf "list length: %d" (List.length client_protos));
      List.iter print_endline client_protos;
      if List.length client_protos > 0 then Some (List.nth client_protos 0)
      else None
    );
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  Unix.bind sock sockaddr;
  Unix.listen sock 100;
  log "listening for connections";
  let (s, caller) = Unix.accept sock in
  let ssl_s = Ssl.embed_socket s ctx in
  let () =
    try Ssl.accept ssl_s with
    | e -> Printexc.to_string e |> print_endline
  in
  let inet_addr_of_sockaddr = function
    | Unix.ADDR_INET (n, _) -> n
    | Unix.ADDR_UNIX _ -> Unix.inet_addr_any
  in
  let inet_addr = inet_addr_of_sockaddr caller in
  let ip = Unix.string_of_inet_addr inet_addr in
  log (Printf.sprintf "openning connection for [%s]" ip);
  let () =
    match Ssl.get_negotiated_alpn_protocol ssl_s with
    | None -> log "no protocol selected"
    | Some proto -> log (Printf.sprintf "selected protocol: %s" proto)
  in
  Ssl.shutdown ssl_s
