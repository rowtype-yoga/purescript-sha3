{
  description = "purescript-sha3";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    purescript-overlay = {
      url = "github:thomashoneyman/purescript-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nixpkgs-purerl = {
      url = "github:purerl/nixpkgs-purerl";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, purescript-overlay, nixpkgs-purerl, ... }:
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

      erlang = pkgs.erlang_27;

      # purerl 0.0.22 pairs with purs 0.15.14. Do not float purs here.
      purs = pkgs.purs-bin.purs-0_15_14;
      purerl = nixpkgs-purerl.packages.${system}.purerl-0-0-22;

      sha3-nif = pkgs.stdenv.mkDerivation {
        pname = "sha3-nif";
        version = "0.1.0";
        src = ./c_src;

        buildInputs = [ erlang ];

        buildPhase = ''
          $CC -O3 -Wall -Wextra -fPIC -shared \
            -I${erlang}/lib/erlang/usr/include \
            sha3_nif.c -o sha3_nif.so
        '';

        installPhase = ''
          mkdir -p $out/lib
          cp sha3_nif.so $out/lib/
        '';
      };

      build-nif = pkgs.writeShellApplication {
        name = "build-nif";
        text = ''
          mkdir -p priv
          cc -O3 -Wall -Wextra -fPIC -shared \
            -I"${erlang}/lib/erlang/usr/include" \
            c_src/sha3_nif.c -o priv/sha3_nif.so
          echo "priv/sha3_nif.so built"
        '';
      };

      test-nif = pkgs.writeShellApplication {
        name = "test-nif";
        runtimeInputs = [ erlang ];
        text = ''
          mkdir -p ebin
          erlc -o ebin erl_src/*.erl
          erl -pa ebin -noshell -eval 'sha3_test:run(), init:stop().'
        '';
      };

      build-erl = pkgs.writeShellApplication {
        name = "build-erl";
        runtimeInputs = [ erlang purerl ];
        text = ''
          rm -rf output ebin
          spago build
          mkdir -p ebin
          erlc -o ebin erl_src/*.erl
          find output -name '*.erl' -print0 | xargs -0 erlc -o ebin
          echo "compiled to ebin/"
        '';
      };

      test-erl = pkgs.writeShellApplication {
        name = "test-erl";
        runtimeInputs = [ erlang ];
        text = ''
          erl -pa ebin -noshell -eval \
            'sha3_test:run(), (test_main@ps:main())(), init:stop().'
        '';
      };

    in {
      legacyPackages = pkgs;

      packages = {
        inherit sha3-nif;
        default = sha3-nif;
      };

      checks = {
        inherit sha3-nif;
      };

      devShell = pkgs.mkShell {
        inherit name;

        buildInputs = with pkgs; [
          esbuild
          nodejs_20
          nixpkgs-fmt
          purs-tidy
          purescript-language-server
          spago-unstable
        ] ++ [
          purs
          erlang
          purerl
          pkgs.rebar3

          build-nif
          test-nif
          build-erl
          test-erl
        ];

        shellHook = ''
          export ERL_INCLUDE_DIR="${erlang}/lib/erlang/usr/include"
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