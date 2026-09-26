open Alcotest
open Util

let test_sockets_sni () =
  let addr = Util.server_thread None in

  let context = Ssl.create_context TLSv1_3 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_client_SNI_hostname ssl "localhost";
  Unix.connect sock addr;
  Ssl.connect ssl;
  Ssl.flush ssl;
  Ssl.shutdown_connection ssl;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error)

let test_sockets_alpn () =
  let addr = Util.server_thread None in
  let context = Ssl.create_context TLSv1_3 Client_context in
  let domain = Unix.domain_of_sockaddr addr in
  let sock = Unix.socket domain Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  Ssl.set_alpn_protos ssl ["http/1.1"];
  Unix.connect sock addr;
  Ssl.connect ssl;
  let negotatiated_proto = Ssl.get_negotiated_alpn_protocol ssl in
  Ssl.flush ssl;
  Ssl.shutdown_connection ssl;
  check bool "no errors" true (Ssl.get_error_string () |> check_ssl_no_error);
  check (option string) "protocol negotiated" (Some "http/1.1")
    negotatiated_proto

(* Runs one handshake against a server using [select], returning how the
   server-side accept ended. *)
let server_accept_with_alpn_select select =
  let listener = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.bind listener (Unix.ADDR_INET (Unix.inet_addr_loopback, 0));
  Unix.listen listener 1;
  let server_context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate server_context "server.pem" "server.key";
  Ssl.set_context_alpn_select_callback server_context select;
  let server_result = ref "not run" in
  let server =
    Thread.create
      (fun () ->
        let sock, _ = Unix.accept listener in
        let ssl = Ssl.embed_socket sock server_context in
        (server_result :=
           match Ssl.accept ssl with
             | () -> "accepted"
             | exception Ssl.Accept_error _ -> "accept error"
             | exception exn -> Printexc.to_string exn);
        Unix.close sock)
      ()
  in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.connect sock (Unix.getsockname listener);
  let ssl = Ssl.embed_socket sock (Ssl.create_context TLSv1_3 Client_context) in
  Ssl.set_alpn_protos ssl ["http/1.1"];
  (try Ssl.connect ssl with Ssl.Connection_error _ -> ());
  Thread.join server;
  Unix.close sock;
  Unix.close listener;
  !server_result

let test_alpn_select_offered () =
  check string "handshake" "accepted"
    (server_accept_with_alpn_select (fun protos -> List.nth_opt protos 0))

let test_alpn_select_raises () =
  check string "handshake" "accept error"
    (server_accept_with_alpn_select (fun _ -> raise Exit))

let test_alpn_select_not_offered () =
  check string "handshake" "accept error"
    (server_accept_with_alpn_select (fun _ -> Some "h2"))

let test_alpn_invalid_protos () =
  let context = Ssl.create_context TLSv1_3 Client_context in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  let ssl = Ssl.embed_socket sock context in
  List.iter
    (fun protos ->
      (match Ssl.set_alpn_protos ssl protos with
        | () -> fail "invalid socket protocols accepted"
        | exception Invalid_argument _ -> ());
      match Ssl.set_context_alpn_protos context protos with
        | () -> fail "invalid context protocols accepted"
        | exception Invalid_argument _ -> ())
    [
      [""];
      [String.make 256 'a'];
      ["http/1.1"; ""];
      List.init 256 (fun _ -> String.make 255 'a');
    ];
  Ssl.set_alpn_protos ssl [String.make 255 'a'];
  Unix.close sock

let () =
  Alcotest.run "Ssl socket functions"
    [
      ( "Sockets",
        [
          test_case "Set client SNI" `Quick test_sockets_sni;
          test_case "ALPN protocols" `Quick test_sockets_alpn;
          test_case "ALPN select offered" `Quick test_alpn_select_offered;
          test_case "ALPN select raises" `Quick test_alpn_select_raises;
          test_case "ALPN select not offered" `Quick
            test_alpn_select_not_offered;
          test_case "ALPN invalid protocols" `Quick test_alpn_invalid_protos;
        ] );
    ]
