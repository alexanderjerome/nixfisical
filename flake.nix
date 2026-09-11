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

      overlays.default = final: prev:
        let
          # Not exposed as an attribute: it is a version pin and two helper
          # strings, not a package, and a consumer's nixpkgs has no use for it.
          infisicalSource = final.callPackage ./nix/pkgs/infisical-source.nix { };
        in
        {
          nixfisical = final.callPackage ./nix/pkgs/nixfisical.nix { };

          # The API, the web UI, and the two joined so the API serves the UI.
          # Separate because the API is useful alone and the UI is cheap to
          # rebuild while the API is not -- see infisical-standalone.nix.
          infisical-backend = final.callPackage ./nix/pkgs/infisical-backend.nix {
            inherit infisicalSource;
          };
          infisical-frontend = final.callPackage ./nix/pkgs/infisical-frontend.nix {
            inherit infisicalSource;
          };
          infisical-standalone = final.callPackage ./nix/pkgs/infisical-standalone.nix {
            inherit infisicalSource;
          };
          # `bump-infisical` is deliberately absent: it rewrites this repo's own
          # source and is only meaningful from a checkout, so it is a flake app
          # rather than something a consumer's nixpkgs should carry.
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
        infisicalSource = pkgs.callPackage ./nix/pkgs/infisical-source.nix { };
        infisical-backend = pkgs.callPackage ./nix/pkgs/infisical-backend.nix {
          inherit infisicalSource;
        };
        infisical-frontend = pkgs.callPackage ./nix/pkgs/infisical-frontend.nix {
          inherit infisicalSource;
        };
        infisical-standalone = pkgs.callPackage ./nix/pkgs/infisical-standalone.nix {
          inherit infisicalSource infisical-backend infisical-frontend;
        };
        bump-infisical = pkgs.callPackage ./nix/pkgs/bump-infisical.nix { };
      in
      {
        packages = {
          inherit nixfisical bump-infisical
            infisical-backend infisical-frontend infisical-standalone;
          default = nixfisical;
        };

        apps.default = {
          type = "app";
          program = "${nixfisical}/bin/nixfisical";
        };

        apps.bump-infisical = {
          type = "app";
          program = "${bump-infisical}/bin/bump-infisical";
          meta.description = "Bump the pinned Infisical release and its hashes";
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
              # Minimal stand-in for the sops-nix options the manifest walk
              # reads, so the check stays free of a sops-nix input. Same
              # merge trick the export module uses.
              #
              # `key` must be modelled, and modelled with sops-nix's default of
              # the attribute name. An earlier stub declared only `sopsFile`,
              # so every secret looked like one whose key was its attribute
              # name -- the check went green on a manifest that could not
              # resolve a single value against a real instance.
              sopsFileStub = { lib, ... }: {
                options.sops.secrets = lib.mkOption {
                  type = lib.types.attrsOf (lib.types.submodule ({ name, ... }: {
                    options.sopsFile = lib.mkOption {
                      type = lib.types.nullOr (lib.types.either lib.types.str lib.types.path);
                      default = null;
                    };
                    options.key = lib.mkOption {
                      type = lib.types.str;
                      default = name;
                    };
                  }));
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
                  # Explicit `key`: the attribute is a descriptive host-side
                  # name, the encrypted file is flat. sopsKey must follow the
                  # key ("api_key"), not the attribute.
                  "cli-proxy/api_key" = {
                    sopsFile = "/fleet/secrets/cli-proxy.yaml";
                    key = "api_key";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "apps";
                      folder = "/cli-proxy";
                      name = "CLI_PROXY_API_KEY";
                      groups = [ "developers" ];
                    };
                  };
                  # Same, with the Infisical name left to default. It must
                  # derive from the resolved key ("mealie"), not the attribute
                  # -- which is why the attribute ends in something else.
                  "infra-db/mealie_pw" = {
                    sopsFile = "/fleet/secrets/infra-db.yaml";
                    key = "mealie";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "databases";
                      folder = "/mealie";
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
                  folder = "/cli-proxy";
                  groups = [ "developers" ];
                  hosts = [ "alpha" ];
                  name = "CLI_PROXY_API_KEY";
                  project = "apps";
                  sopsFile = "/fleet/secrets/cli-proxy.yaml";
                  sopsKey = "api_key";
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
                {
                  environment = "prod";
                  folder = "/mealie";
                  groups = [ ];
                  hosts = [ "alpha" ];
                  name = "mealie";
                  project = "databases";
                  sopsFile = "/fleet/secrets/infra-db.yaml";
                  sopsKey = "mealie";
                }
              ];
            in
            if actual == expected
            then "echo ok > $out"
            else
              throw ''
                nixfisical manifest check failed.
                  expected: ${expected}
                  actual:   ${actual}
              ''
          );
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
