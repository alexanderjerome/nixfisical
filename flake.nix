{
  description = "Declarative Infisical for NixOS — server module, self-healing bootstrap, and a sops-driven secret reconciler";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    let
      # The declaration/manifest layer is pure — it only needs `lib`, so it is
      # available without a system and callable from a consumer's flake before
      # any package is built.
      nixfisicalLib = import ./nix/lib { lib = nixpkgs.lib; };
    in
    {
      lib = nixfisicalLib;

      nixosModules = {
        default = ./nix/modules;
        # Run a self-hosted Infisical instance.
        server = ./nix/modules/server.nix;
        # Add `sops.secrets.<key>.infisical` so secrets can be annotated for
        # export. Import this on every host you want to export from.
        export = ./nix/modules/export.nix;
      };

      overlays.default = final: prev: {
        nixfisical = final.callPackage ./nix/pkgs/nixfisical.nix { };
      };

      # Render a fleet's manifest as a flake app:
      #
      #   packages.infisical-manifest =
      #     nixfisical.mkManifestApp {
      #       inherit pkgs;
      #       nixosConfigurations = self.nixosConfigurations;
      #     };
      #
      #   nix run .#infisical-manifest            # JSON (feeds `nixfisical sync`)
      #   nix run .#infisical-manifest -- table   # human review
      #
      # The JSON is baked at eval time and contains no decrypted values —
      # only SOPS key paths and their routing.
      mkManifestApp = { pkgs, nixosConfigurations, validate ? true }:
        let
          raw = nixfisicalLib.manifestOf nixosConfigurations;
          manifest = if validate then nixfisicalLib.assertManifest raw else raw;
          json = builtins.toJSON manifest;
        in
        pkgs.writeShellApplication {
          name = "infisical-manifest";
          runtimeInputs = [ pkgs.jq pkgs.util-linux ];
          text = ''
            M=${pkgs.lib.escapeShellArg json}
            case "''${1:-json}" in
              json)
                printf '%s' "$M" | jq '.'
                ;;
              table)
                {
                  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    PROJECT ENV FOLDER NAME GROUPS "SOPS FILE" "SOPS KEY"
                  printf '%s' "$M" | jq -r '
                    .[] | [.project, .environment, .folder, .name,
                           (.groups | join(",")), .sopsFile, .sopsKey] | @tsv'
                } | column -t -s "$(printf '\t')"
                echo ""
                echo "exported secrets: $(printf '%s' "$M" | jq 'length')"
                ;;
              *)
                echo "usage: infisical-manifest [json|table]" >&2
                exit 1
                ;;
            esac
          '';
        };
    }
    // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        nixfisical = pkgs.callPackage ./nix/pkgs/nixfisical.nix { };
      in
      {
        packages = {
          inherit nixfisical;
          default = nixfisical;
        };

        apps.default = {
          type = "app";
          program = "${nixfisical}/bin/nixfisical";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            nixfisical
            pkgs.sops
            pkgs.age
            pkgs.jq
            # The upstream CLI, for poking at an instance by hand.
            pkgs.infisical
            (pkgs.python3.withPackages (ps: [ ps.click ps.httpx ps.pyyaml ]))
          ];
          shellHook = ''
            echo "nixfisical dev shell — 'nixfisical --help' for the CLI."
          '';
        };

        checks = {
          package = nixfisical;

          # Evaluate the export module standalone and assert the manifest
          # walk produces what we expect: the name defaulting, the per-secret
          # sopsFile, the host union, and the exclusion of unannotated
          # secrets. Catches regressions in nix/lib without needing a full
          # NixOS system or sops-nix.
          manifest = pkgs.runCommand "nixfisical-manifest-check" { } (
            let
              # Minimal stand-in for the one sops-nix option the manifest walk
              # reads, so the check stays free of a sops-nix input. Same
              # merge trick the export module uses.
              sopsFileStub = { lib, ... }: {
                options.sops.secrets = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.submodule {
                    options.sopsFile = lib.mkOption {
                      type = lib.types.nullOr (lib.types.either lib.types.str lib.types.path);
                      default = null;
                    };
                  });
                };
              };

              mkHost = host: secrets: {
                config = (nixpkgs.lib.evalModules {
                  modules = [
                    ./nix/modules/export.nix
                    sopsFileStub
                    { sops.secrets = secrets; }
                  ];
                }).config;
              };

              shared = {
                "services/api/token" = {
                  sopsFile = "/fleet/secrets/api.yaml";
                  infisical = nixfisicalLib.mkInfisical {
                    project = "apps";
                    folder = "/api";
                    groups = [ "developers" ];
                  };
                };
              };

              configurations = {
                alpha = mkHost "alpha" (shared // {
                  "dbs/main/password" = {
                    sopsFile = "/fleet/secrets/dbs.yaml";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "databases";
                      name = "MAIN_PASSWORD";
                    };
                  };
                  # Unannotated: must never appear in the manifest.
                  "internal/root_key" = { sopsFile = "/fleet/secrets/dbs.yaml"; };
                });
                beta = mkHost "beta" shared;
              };

              manifest = nixfisicalLib.assertManifest
                (nixfisicalLib.manifestOf configurations);

              actual = builtins.toJSON manifest;

              # Ordered by the dedupe identity ("<sopsFile>#<sopsKey>"), so
              # api.yaml sorts ahead of dbs.yaml.
              expected = builtins.toJSON [
                {
                  environment = "prod";
                  folder = "/api";
                  groups = [ "developers" ];
                  hosts = [ "alpha" "beta" ];
                  name = "token";
                  project = "apps";
                  sopsFile = "/fleet/secrets/api.yaml";
                  sopsKey = "services/api/token";
                }
                {
                  environment = "prod";
                  folder = "/";
                  groups = [ ];
                  hosts = [ "alpha" ];
                  name = "MAIN_PASSWORD";
                  project = "databases";
                  sopsFile = "/fleet/secrets/dbs.yaml";
                  sopsKey = "dbs/main/password";
                }
              ];
            in
            if actual == expected
            then "echo ok > $out"
            else throw ''
              nixfisical manifest check failed.
                expected: ${expected}
                actual:   ${actual}
            ''
          );
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
