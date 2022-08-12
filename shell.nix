{ packages
, lib
, mkShell
, release-mode ? false
, cacert
, curl
, ocamlPackages
, git
, opam
}:

mkShell {
  OCAMLRUNPARAM = "b";
  inputsFrom = packages;
  buildInputs =
    (with ocamlPackages; [
      merlin
      ocamlformat
      utop
      alcotest
    ]) ++ lib.optional release-mode [
      cacert
      curl
      ocamlPackages.dune-release
      git
      opam
    ];
}
