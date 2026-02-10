{
  description = "purescript-sha3";

  inputs = {

    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";


    purescript-overlay = {
      url = "github:thomashoneyman/purescript-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
        
    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, purescript-overlay, ... }:
    {

    } // flake-utils.lib.eachSystem ["x86_64-linux" "x86_64-darwin" "aarch64-darwin"] (system: let
      
      name = "purescript-sha3";
      lib = nixpkgs.lib;

      overlays = [
        purescript-overlay.overlays.default
      ];
      
      pkgs = import nixpkgs {
        inherit system overlays;
      };

      # Build purescm 1.12.0 from npm
      # nixpkgs has outdated 1.8.2 which is incompatible with the current package set
      purescm = pkgs.callPackage ./nix/purescm/package.nix {};

    in {
      legacyPackages = pkgs;

      devShell = pkgs.mkShell {
        inherit name;
        CHEZ_DYLD_LIBRARY_PATH = "${pkgs.pcre2.out}/lib:${pkgs.icu.out}/lib";
        LD_LIBRARY_PATH = "${pkgs.pcre2.out}/lib:${pkgs.icu.out}/lib";

        buildInputs = with pkgs; [

          esbuild
          nodejs_20
          nixpkgs-fmt
          purs
          purs-tidy
          purs-backend-es
          purescript-language-server
          spago-unstable

          purescm  # custom 1.12.0 build (replaces nixpkgs version)
          chez
          pcre2
          icu

        ] ++ (pkgs.lib.optionals (system == "aarch64-darwin")
          (with pkgs.darwin.apple_sdk.frameworks; [
            Cocoa
            CoreServices
          ]));
          shellHook = ''

          '';
      };
    });

  nixConfig = {
    extra-experimental-features = ["nix-command flakes" "ca-derivations"];
    allow-import-from-derivation = "true";
    extra-substituters = [
      "https://cache.iog.io"
      "https://cache.zw3rk.com"
      "https://cache.nixos.org"
      "https://hercules-ci.cachix.org"
    ];
    extra-trusted-public-keys = [
      "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
      "loony-tools:pr9m4BkM/5/eSTZlkQyRt57Jz7OMBxNSUiMC4FkcNfk="
      "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
      "hercules-ci.cachix.org-1:ZZeDl9Va+xe9j+KqdzoBZMFJHVQ42Uu/c/1/KMC5Lw0="
    ];
  };
}