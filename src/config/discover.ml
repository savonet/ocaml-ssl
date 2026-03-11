module C = Configurator.V1

let directory_exists fsp = Sys.file_exists fsp && Sys.is_directory fsp

let file_exists path =
  try Sys.file_exists path with _ -> false

let find_map f xs =
  let rec go = function
    | [] -> None
    | x :: xs ->
      (match f x with
      | Some _ as y -> y
      | None -> go xs)
  in
  go xs

let lib_paths dir =
  let pick names =
    List.find_map
      (fun name ->
        let path = Filename.concat dir name in
        if file_exists path then Some path else None)
      names
  in
  match pick [ "libssl.dylib"; "libssl.so" ], pick [ "libcrypto.dylib"; "libcrypto.so" ] with
  | Some ssl, Some crypto -> Some [ ssl; crypto ]
  | _ -> None

let normalize_libs c libs =
  if C.ocaml_config_var_exn c "system" <> "macosx"
  then libs
  else
    let dirs =
      List.filter_map
        (fun flag ->
          if String.starts_with ~prefix:"-L" flag
          then Some (String.sub flag 2 (String.length flag - 2))
          else None)
        libs
    in
    match find_map lib_paths dirs with
    | Some libs -> libs
    | None -> libs

let default c : C.Pkg_config.package_conf =
  if C.ocaml_config_var_exn c "system" = "macosx"
  then
    if directory_exists "/usr/local/opt/openssl"
    then
      { libs =
          (match lib_paths "/usr/local/opt/openssl/lib" with
          | Some libs -> libs
          | None -> [ "-L/usr/local/opt/openssl/lib" ])
      ; cflags = [ "-I/usr/local/opt/openssl/include" ]
      }
    else
      { libs =
          (match lib_paths "/opt/local/lib" with
          | Some libs -> libs
          | None -> [ "-L/opt/local/lib" ])
      ; cflags = [ "-I/opt/local/include" ]
      }
  else { libs = [ "-lssl"; "-lcrypto" ]; cflags = [] }

let () =
  C.main ~name:"ssl" (fun c ->
      let default = default c in
      let conf =
        match C.Pkg_config.get c with
        | None -> default
        | Some pc ->
          (match C.Pkg_config.query pc ~package:"openssl" with
          | Some s -> { s with libs = normalize_libs c s.libs }
          | None -> default)
      in
      C.Flags.write_sexp "c_library_flags.sexp" conf.libs;
      C.Flags.write_sexp "c_flags.sexp" conf.cflags)
