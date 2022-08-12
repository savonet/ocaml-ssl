{
  description = "OCaml-SSL Nix Flake";

  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.nixpkgs.inputs.flake-utils.follows = "flake-utils";
  inputs.nixpkgs.url = "github:anmonteiro/nix-overlays";

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages."${system}";
      in
      rec {
        defaultPackage = pkgs.callPackage ./nix { };
        devShells = {
          default = pkgs.callPackage ./shell.nix {
            packages = [ defaultPackage ];
          };

          release = pkgs.callPackage ./shell.nix {
            packages = [ defaultPackage ];
            release-mode = true;
          };
        };
      });
}
