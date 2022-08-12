{ ocamlVersion }:

let
  lock = builtins.fromJSON (builtins.readFile ./../../flake.lock);
  src = fetchGit {
    url = with lock.nodes.nixpkgs.locked; "https://github.com/${owner}/${repo}";
    inherit (lock.nodes.nixpkgs.locked) rev;
    # inherit (lock.nodes.nixpkgs.original) ref;
    allRefs = true;
  };

  pkgs = import "${src}" {
    extraOverlays = [
      (self: super: {
        h2spec = super.callPackage ../h2spec.nix { };
        ocamlPackages = super.ocaml-ng."ocamlPackages_${ocamlVersion}";
      })
    ];
  };


  inherit (pkgs) callPackage lib stdenv fetchTarball ocamlPackages h2spec;
in
callPackage ./.. { doCheck = true; }
