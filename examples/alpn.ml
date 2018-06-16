
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
  let rec first_match l1 = function
    | [] -> None
    | x::_ when List.mem x l1 -> Some x
    | _::xs -> first_match l1 xs
  in
  Ssl.set_context_alpn_select_callback ctx (fun client_protos ->
      first_match client_protos proto_list
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

let () =
  let usage = "usage: ./alpn (server|client) protocol[,protocol]" in
  let split_on_char sep s =
    let r = ref [] in
    let j = ref (String.length s) in
    for i = String.length s - 1 downto 0 do
      if s.[i] = sep then begin
        r := String.sub s (i + 1) (!j - i - 1) :: !r;
        j := i
      end
    done;
    String.sub s 0 !j :: !r
  in
  let typ = ref "" in
  let protocols = ref [] in
  Arg.parse [
    "-t", Arg.String (fun t -> typ := t), "Type (server or client)";
    "-p", Arg.String (fun p -> protocols := split_on_char ',' p), "Comma-separated protocols";
  ] (fun _ -> ()) usage;
  match !typ with
  | "server" -> test_server !protocols
  | "client" -> test_client !protocols
  | _ -> failwith "Invalid type, use server or client."

(* Usage:
ocamlfind ocamlc alpn.ml -g -o alpn -package ssl -linkpkg -ccopt -L/path/to/openssl/lib -cclib -lssl -cclib -lcrypto
./alpn -t server -p h2,http/1.1
./alpn -t client -p h2/http/1.1
*)
