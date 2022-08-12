{ stdenv
, lib
, ocamlPackages
, openssl-oc
, doCheck ? false
, pkg-config
}:

with ocamlPackages;

buildDunePackage {
  pname = "ssl";
  version = "n/a";

  useDune2 = true;

  src = ../.;

  nativeBuildInputs = [ ocaml dune findlib pkg-config ];
  buildInputs = [ dune-configurator ];
  propagatedBuildInputs = [
    openssl-oc.dev
  ];
  checkInputs = [ alcotest ];

  inherit doCheck;
}
