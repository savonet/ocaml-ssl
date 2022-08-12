{ packages
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
    (if release-mode then [
      cacert
      curl
      ocamlPackages.dune-release
      git
      opam
    ] else [ ]) ++
    (with ocamlPackages; [ merlin ocamlformat utop ]);
}
