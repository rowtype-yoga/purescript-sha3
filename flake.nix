{
  description = "purescript-sha3 (phpurs / PHP backend)";

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

    } // flake-utils.lib.eachSystem [ "x86_64-linux" "x86_64-darwin" "aarch64-darwin" ] (system:
      let
        name = "purescript-sha3";

        overlays = [ purescript-overlay.overlays.default ];

        pkgs = import nixpkgs { inherit system overlays; };

        php = pkgs.php83;

        # PHP wrapped with OPcache + tracing JIT enabled for the CLI.
        # Interpreted PHP does ~7.5 MB/s on this Keccak; the JIT ~40 MB/s.
        php-jit = pkgs.writeShellScriptBin "php-jit" ''
          exec ${php}/bin/php \
            -d opcache.enable_cli=1 \
            -d opcache.jit=tracing \
            -d opcache.jit_buffer_size=64M \
            "$@"
        '';

        run-tests = pkgs.writeShellScriptBin "run-tests" ''
          set -euo pipefail
          spago build
          php-jit output/main.php
        '';

        run-bench = pkgs.writeShellScriptBin "run-bench" ''
          set -euo pipefail
          spago build
          BENCH=1 php-jit output/main.php
        '';
      in
      {
        legacyPackages = pkgs;

        devShell = pkgs.mkShell {
          inherit name;

          buildInputs = with pkgs; [
            nodejs_20 # phpurs is an npm package; also runs the compiler
            nixpkgs-fmt
            purs
            purs-tidy
            purescript-language-server
            spago-unstable

            php
            php-jit
            run-tests
            run-bench
          ];

          shellHook = ''
            # phpurs is installed per-project (npm install); spago invokes
            # the `phpurs` command, so the local bin dir must be on PATH.
            export PATH="$PWD/node_modules/.bin:$PATH"
            if [ ! -x node_modules/.bin/phpurs ]; then
              echo "phpurs not installed — run: npm install"
            fi
          '';
        };
      });

  nixConfig = {
    extra-experimental-features = [ "nix-command flakes" "ca-derivations" ];
    allow-import-from-derivation = "true";
  };
}