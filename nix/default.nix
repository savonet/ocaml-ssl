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
  nativeCheckInputs = [ openssl-oc ];
  checkInputs = [ alcotest ];

  inherit doCheck;
  checkPhase = ''
    dune build -p ssl @runtest @github_action_tests ''${enableParallelBuilding:+-j $NIX_BUILD_CORES}
  '';
}
