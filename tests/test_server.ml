let server_listen addr =
  Ssl.init ();
  let socket = Unix.socket (Unix.PF_INET) Unix.SOCK_STREAM 0 in
  let addr = addr in
  Unix.bind socket addr;
  Unix.listen socket 1;
  let listen = Unix.accept socket in
  let context = Ssl.create_context TLSv1_3 Server_context in
  Ssl.use_certificate context "ca.pem" "ca.key";
  let ssl = Ssl.embed_socket (fst listen) context in
  Ssl.accept ssl

let server_thread addr = 
  Thread.create server_listen addr
