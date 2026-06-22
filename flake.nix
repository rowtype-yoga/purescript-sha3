{
  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url  = "github:numtide/flake-utils";
    purescript-overlay = {
      url = "github:harryprayiv/purescript-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    purs-wasm-backend.url = "github:harryprayiv/purescript-backend-wasm";
  };

  outputs = { self, nixpkgs, flake-utils, purescript-overlay, purs-wasm-backend }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            purescript-overlay.overlays.default
          ];
        };
        purs-wasm = purs-wasm-backend.packages.${system}.purs-wasm;
      in
        {
          packages = {
            inherit purs-wasm;
            default = purs-wasm;
          };
          apps = {
            purs-wasm = purs-wasm-backend.apps.${system}.purs-wasm;
            default = purs-wasm-backend.apps.${system}.purs-wasm;
          };
          devShells.default =
            let
              sha3-check = pkgs.writeShellScriptBin "sha3-check" ''
                set -euo pipefail
                spago build
                node copy-foreigns.mjs output-wasm
                node -e 'import("./output-wasm/index.mjs").then(m => m.exports.main())'
              '';
              sha3-bench = pkgs.writeShellScriptBin "sha3-bench" ''
                set -euo pipefail
                backend="''${PURS_WASM_DEV:-/home/bismuth/git/purescript-backend-wasm/purs-wasm/index.dev.js}"
                spago build
                node "$backend" build -p node -E -I output -O output-bench -e Bench
                node copy-foreigns.mjs output-bench
                node bench.mjs
              '';
            in
            pkgs.mkShellNoCC {
              buildInputs = with pkgs; [
                purs-bin.purs-0_15_16
                spago
                purs-tidy-bin.purs-tidy-0_10_0
                purs-backend-es
                esbuild
                nodejs_24
                pnpm
                gnuplot
              ] ++ [ purs-wasm sha3-check sha3-bench ];
            };
        }
        
    );
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