{
  inputs = {
    nixpkgs.url      = "github:NixOS/nixpkgs/nixos-25.11";
    flake-utils.url  = "github:numtide/flake-utils";
    purescript-overlay = {
      url = "github:harryprayiv/purescript-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # nix-claude-code.url = "github:ryoppippi/nix-claude-code";
    # Your fork — has the Data.Int.Bits intrinsics + i32Xor/Shl/Shr bindings.
    # Deliberately NOT following our nixpkgs: it carries its own locked inputs
    # (specific purs version, etc.) that its build needs.
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
        # claude-code = nix-claude-code.packages.${system}.default;
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
          devShells.default = pkgs.mkShellNoCC {
            buildInputs = with pkgs; [
              purs-bin.purs-0_15_16
              spago
              purs-tidy-bin.purs-tidy-0_10_0
              purs-backend-es
              esbuild
              nodejs_24
              pnpm
              gnuplot
            ] ++ [ purs-wasm ];
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

# {
#   description = "purescript-sha3";

#   inputs = {

#     nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";


#     purescript-overlay = {
#       url = "github:thomashoneyman/purescript-overlay";
#       inputs.nixpkgs.follows = "nixpkgs";
#     };
        
#     flake-utils.url = "github:numtide/flake-utils";
#     flake-compat = {
#       url = "github:edolstra/flake-compat";
#       flake = false;
#     };
#   };

#   outputs = { self, nixpkgs, flake-utils, purescript-overlay, ... }:
#     {

#     } // flake-utils.lib.eachSystem ["x86_64-linux" "x86_64-darwin" "aarch64-darwin"] (system: let
      
#       name = "purescript-sha3";
#       lib = nixpkgs.lib;

#       overlays = [
#         purescript-overlay.overlays.default
#       ];
      
#       pkgs = import nixpkgs {
#         inherit system overlays;
#       };


#     in {
#       legacyPackages = pkgs;

#       devShell = pkgs.mkShell {
#         inherit name;
        

#         buildInputs = with pkgs; [

#           esbuild
#           nodejs_20
#           nixpkgs-fmt
#           purs
#           purs-tidy
#           purs-backend-es
#           purescript-language-server
#           spago-unstable # new spago
#           # spago
      

#         ] ++ (pkgs.lib.optionals (system == "aarch64-darwin")
#           (with pkgs.darwin.apple_sdk.frameworks; [
#             Cocoa
#             CoreServices
#           ]));
#           shellHook = ''

#           '';
#       };
#     });

#   nixConfig = {
#     extra-experimental-features = ["nix-command flakes" "ca-derivations"];
#     allow-import-from-derivation = "true";
#     extra-substituters = [
#       "https://cache.iog.io"
#       "https://cache.zw3rk.com"
#       "https://cache.nixos.org"
#       "https://hercules-ci.cachix.org"
#     ];
#     extra-trusted-public-keys = [
#       "hydra.iohk.io:f/Ea+s+dFdN+3Y/G+FDgSq+a5NEWhJGzdjvKNGv0/EQ="
#       "loony-tools:pr9m4BkM/5/eSTZlkQyRt57Jz7OMBxNSUiMC4FkcNfk="
#       "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
#       "hercules-ci.cachix.org-1:ZZeDl9Va+xe9j+KqdzoBZMFJHVQ42Uu/c/1/KMC5Lw0="
#     ];
#   };
# }