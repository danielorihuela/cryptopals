{
  description = "Nix flake for Crafting Interpreters implementations";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      fenix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        fenixPkgs = fenix.packages.${system};
        rustNightly = fenixPkgs.complete.withComponents [
          "cargo"
          "rustc"
          "rust-src"
        ];
      in
      {
        devShells = {
          default = pkgs.mkShell {
            buildInputs = [ rustNightly ];
            packages = with pkgs; [
              cargo
              rustc
              rustfmt
              clippy
            ];
          };
        };
      }
    );
}
