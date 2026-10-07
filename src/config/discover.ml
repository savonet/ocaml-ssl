module C = Configurator.V1

let directory_exists fsp = Sys.file_exists fsp && Sys.is_directory fsp
let libs = ["-lssl"; "-lcrypto"]

let default c : C.Pkg_config.package_conf =
  let prefix =
    if C.ocaml_config_var_exn c "system" = "macosx" then
      List.find_opt directory_exists
        ["/opt/homebrew/opt/openssl"; "/usr/local/opt/openssl"; "/opt/local"]
    else None
  in
  match prefix with
    | Some prefix ->
        {
          libs = ("-L" ^ Filename.concat prefix "lib") :: libs;
          cflags = ["-I" ^ Filename.concat prefix "include"];
        }
    | None -> { libs; cflags = [] }

let () =
  C.main ~name:"ssl" (fun c ->
      let conf =
        match
          Option.bind (C.Pkg_config.get c) (fun pc ->
              C.Pkg_config.query pc ~package:"openssl")
        with
          | Some conf -> conf
          | None ->
              let conf = default c in
              Printf.eprintf
                "Warning: pkg-config could not find openssl, building with: %s\n"
                (String.concat " " (conf.cflags @ conf.libs));
              conf
      in
      C.Flags.write_sexp "c_library_flags.sexp" conf.libs;
      C.Flags.write_sexp "c_flags.sexp" conf.cflags)
