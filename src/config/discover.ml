module C = Configurator.V1

let directory_exists fsp =
  Sys.file_exists fsp && Sys.is_directory fsp

let default c : C.Pkg_config.package_conf =
  let cflags = match Sys.getenv_opt "CFLAGS" with
  | Some cflags -> [ cflags ]
  | None -> []
  in
  let libs = match Sys.getenv_opt "LDFLAGS" with
  | Some libs -> [ libs ]
  | None -> []
  in
  if C.ocaml_config_var_exn c "system" = "macosx" then
    if directory_exists "/usr/local/opt/openssl" then
      { libs = ["-L/usr/local/opt/openssl/lib"] @ libs
      ; cflags = ["-I/usr/local/opt/openssl/include"] @ cflags
      }
    else
      { libs = ["-L/opt/local/lib"] @ libs
      ; cflags = ["-I/opt/local/include"] @ cflags
      }
  else
    { libs   = ["-lssl"; "-lcrypto"] @ libs
    ; cflags = cflags
    }

let prog fun_name =
  Printf.sprintf {c|
#include <openssl/ssl.h>
int main(int argc, char **argv) {
  void *foo = %s;
  return 0;
}|c} fun_name

let function_tests =
  [ "TLSv1_1_method", "HAVE_TLS11"
  ; "TLSv1_2_method", "HAVE_TLS12"
  ; "TLSv1_3_method", "HAVE_TLS13"
  ; "EC_KEY_free", "HAVE_EC"
  ]

let macro_tests =
  [ "SSL_set_tlsext_host_name", "HAVE_SNI"
  ]

let () =
  C.main ~name:"ssl" (fun c ->
      let default = default c in
      let conf =
        match C.Pkg_config.get c with
        | None -> default
        | Some pc ->
          begin match (C.Pkg_config.query pc ~package:"openssl") with
            | Some s -> s
            | None -> default
          end
      in
      let results =
        C.C_define.import c
          ~c_flags:conf.cflags
          ~includes:["openssl/ssl.h"]
          (List.map (fun (c, _) -> (c, C.C_define.Type.Switch))
            macro_tests)
      in
      let defines =
        List.combine macro_tests results
        |> List.map (fun ((name, const), (name', value)) ->
            assert (name = name');
            (const, value))
      in
      let defines =
        List.fold_left (fun acc (fun_name, var_name) ->
            let defined =
              prog fun_name
              |> C.c_test c ~c_flags:conf.cflags ~link_flags:conf.libs
            in
            ( var_name
            , C.C_define.Value.Switch defined
            ) :: acc
          ) defines function_tests
      in
      C.C_define.gen_header_file c ~fname:"ocaml_ssl.h" defines;
      C.Flags.write_sexp "c_library_flags.sexp" conf.libs;
      C.Flags.write_sexp "c_flags.sexp" conf.cflags)
