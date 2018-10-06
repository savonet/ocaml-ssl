module C = Configurator.V1

let () =
  C.main ~name:"ssl" (fun c ->
      let libPath = Sys.getenv "OPENSSL_LIB_PATH" in
      let includePath = Sys.getenv "OPENSSL_INCLUDE_PATH" in
      let libs = ["-L" ^ libPath; "-lssl"; "-lcrypto"] in
      let cflags = ["-I" ^ includePath] in
      C.Flags.write_sexp "c_library_flags.sexp" libs;
      C.Flags.write_sexp "c_flags.sexp" cflags)
