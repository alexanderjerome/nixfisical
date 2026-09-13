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
      # `extraSecrets` is a list of `lib.mkExportOnly` results: secrets to
      # export that no host declares. See the comment on `mkExportOnly` for
      # when that is the honest thing to do rather than a shortcut.
      mkManifestApp = { pkgs, nixosConfigurations, extraSecrets ? [ ], validate ? true }:
        let
          raw = nixfisicalLib.manifestFrom { inherit nixosConfigurations extraSecrets; };
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

      # The same manifest, pushed:
      #
      #   packages.infisical-sync = nixfisical.mkSyncApp {
      #     inherit pkgs;
      #     nixosConfigurations = self.nixosConfigurations;
      #     url = "https://infisical.example.org";
      #   };
      #
      #   nix run .#infisical-sync -- --dry-run   # licence table, then what would change
      #   nix run .#infisical-sync                # converge
      #
      # `sync`, then `sync-access`. The ordering is not stylistic: `sync-access`
      # grants a group access to a project, so the project has to exist, and
      # `sync` is what creates it -- run the other way round, a first
      # convergence grants nothing and reports no error.
      #
      # Under `--dry-run` the full `license` table is printed in front of both.
      # Only under `--dry-run`: it is twenty-five lines of reference material
      # that does not change between runs, and `sync-access` prints the one line
      # of it that does ("licence: none ...") on every run regardless. Putting
      # it on the converge path would mean an operator reading past two screens
      # of unchanged output to reach the two lines that say what happened, which
      # is how output stops being read at all.
      #
      # Nothing is lost by leaving it off the converge path. It is a report, not
      # a gate -- an unlicensed instance is the normal case and `sync` skips
      # what the plan forbids on its own -- and it is not the early
      # authentication check it looks like either, because `sync` logs in before
      # it writes anything, so a missing age key or an expired sync identity
      # fails there just as cleanly.
      #
      # THIS PRUNES. `sync` deletes secrets the manifest no longer declares, so
      # deleting a `mkInfisical` annotation deletes the secret from Infisical on
      # the next run. That is the declarative contract working, and it is still
      # worth knowing before the first unattended run. `--dry-run` names every
      # deletion.
      #
      # What it deliberately will not do is create a group. That needs
      # `--create-missing-groups`, which writes to Infisical's Postgres behind
      # the API, and a hammer that size should be swung by hand, once, not
      # folded into the command an operator runs after every change.
      #
      # Runs on the operator's machine, not on the instance: the decryption is
      # local and uses the operator's age key, which no host has.
      mkSyncApp =
        { pkgs
        , nixosConfigurations
        , url
          # Secrets to export that no host declares; see `lib.mkExportOnly`.
          # They are pruned like any other entry: drop one here and the next
          # sync deletes it from Infisical.
        , extraSecrets ? [ ]
        , validate ? true
        , adminFile ? "secrets/infisical-admin.yaml"
          # The age identity to decrypt with, if SOPS_AGE_KEY_FILE is not
          # already set. Null leaves sops to its own default,
          # ~/.config/sops/age/keys.txt.
          #
          # Worth setting for an estate that keeps a per-repo key, because the
          # failure it prevents does not look like what it is. Unset, sops
          # reports a missing keyring and a keyring holding the wrong key
          # identically -- twenty lines of "Recovery failed because no master
          # key was able to decrypt the file", which reads like a corrupt file
          # and means neither. A flake app is run from outside any dev shell by
          # definition, so it is the likeliest place to meet that.
        , ageKeyFile ? null
          # The humans `sync-access` puts on every project it manages. Null
          # means "read it from the admin file", which works for an INSTANCE
          # admin file and cannot work for a PER-ORG one: `add-org`
          # deliberately omits the admin block, so there is no email in there to
          # read. A consumer syncing into its own organization on a shared
          # instance is exactly that case and must set this.
          #
          # Set it to `false` to pass --no-operator instead, accepting projects
          # whose only member is the sync machine identity -- which is to say,
          # projects no human can see. That is a real choice for an unattended
          # estate and a bad surprise anywhere else.
          #
          # Four shapes, because on an unlicensed instance this is not just how
          # the operator keeps visibility, it is the ONLY ungated way to give
          # any human access at all -- group creation needs a licence, this
          # does not. So it has to express more than one person:
          #
          #   operator = "admin@example.org";          one person, default role
          #   operator = false;                        nobody
          #   operator = [ "a@example.org" { email = "dev@example.org";
          #                                  role  = "viewer"; } ];
          #
          # A list element is either a bare email (taking --operator-role) or
          # `{ email; role; }`. The attrset is rendered to the `EMAIL:ROLE`
          # form the CLI parses, so the parsing lives in exactly one place;
          # a bare string is passed through, which means a literal
          # "dev@example.org:viewer" also works if you prefer it.
          #
          # Everyone named must ALREADY be a member of the organization. This
          # adds a person to a project; it does not invite them to the org.
        , operator ? null
          # Role for any operator that does not name one. Left null to use the
          # CLI's own default (`admin`), which is right for the person who
          # administers the instance and wrong for everyone else -- which is
          # why a developer should carry their own `role` rather than this
          # being lowered fleet-wide.
        , operatorRole ? null
          # Defaults to this flake's own build so a consumer needs neither the
          # overlay nor a matching nixpkgs. Pass `pkgs.nixfisical` if you have it.
        , nixfisical ? self.packages.${pkgs.stdenv.hostPlatform.system}.nixfisical
        }:
        let
          manifestApp = self.mkManifestApp {
            inherit pkgs nixosConfigurations extraSecrets validate;
          };
          inherit (pkgs) lib;
          # An operator entry -> the `EMAIL[:ROLE]` string the CLI parses.
          # Rejecting an attrset without `email` here rather than emitting
          # "null:viewer" and letting the CLI complain: the Nix call site is
          # where the typo is, and a consumer reading a shell error out of a
          # generated script has a much worse time finding it.
          operatorArg = entry:
            if builtins.isString entry then entry
            else if builtins.isAttrs entry then
              (if !(entry ? email) then
                throw
                  ("nixfisical.mkSyncApp: an `operator` attrset needs an "
                  + "`email` field; got ${builtins.toJSON entry}")
              else if entry ? role && entry.role != null
              then "${entry.email}:${entry.role}"
              else entry.email)
            else
              throw ("nixfisical.mkSyncApp: `operator` list elements must be "
              + "strings or { email; role ? null; } attrsets");
          # Only `sync-access` takes these; `sync` would reject them, which is
          # why they are baked in here rather than left to the caller's "$@".
          accessArgs =
            (if operator == null then ""
            else if operator == false then " --no-operator"
            else
              lib.concatMapStrings
                (entry: " --operator ${lib.escapeShellArg (operatorArg entry)}")
                (if builtins.isList operator then operator else [ operator ]))
            + lib.optionalString (operatorRole != null)
              " --operator-role ${lib.escapeShellArg operatorRole}";
        in
        pkgs.writeShellApplication {
          name = "infisical-sync";
          # coreutils for `mktemp`. writeShellApplication only prepends to the
          # ambient PATH, so leaving it out works everywhere it is tried and
          # depends on the caller's environment anyway.
          runtimeInputs = [ manifestApp nixfisical pkgs.coreutils ];
          text = ''
            # --dry-run is the only flag, because it is the only one both
            # subcommands accept. Anything else belongs on `nixfisical` itself,
            # where the help text says which subcommand it applies to.
            case "''${1-}" in
              ""|--dry-run) ;;
              *)
                echo "usage: infisical-sync [--dry-run]" >&2
                exit 1
                ;;
            esac

            ${pkgs.lib.optionalString (ageKeyFile != null) ''
            # `:=` and not `=`: an operator who set SOPS_AGE_KEY_FILE meant it,
            # and a dev shell that already exports one keeps winning.
            : "''${SOPS_AGE_KEY_FILE:=${ageKeyFile}}"
            if [ -f "$SOPS_AGE_KEY_FILE" ]; then
              export SOPS_AGE_KEY_FILE
            else
              # Warn, but do not export and do not exit. SOPS_AGE_KEY and the
              # ssh-key paths are still live, so an operator with a working
              # setup that is not this one must not be broken by a default --
              # and pointing the variable at a file that is not there would
              # narrow sops' search rather than widen it.
              echo "infisical-sync: no age identity at $SOPS_AGE_KEY_FILE;" \
                   "falling back to sops' own search" >&2
            fi
            ''}
            # A file rather than a pipe: both subcommands read the manifest, and
            # `-` can only be consumed once.
            manifest=$(mktemp)
            trap 'rm -f "$manifest"' EXIT
            infisical-manifest json > "$manifest"

            if [ "''${1-}" = "--dry-run" ]; then
              nixfisical --url ${pkgs.lib.escapeShellArg url} \
                --admin-file ${pkgs.lib.escapeShellArg adminFile} license
              echo ""
            fi

            nixfisical --url ${pkgs.lib.escapeShellArg url} \
              --admin-file ${pkgs.lib.escapeShellArg adminFile} \
              sync --manifest "$manifest" "$@"
            echo ""
            nixfisical --url ${pkgs.lib.escapeShellArg url} \
              --admin-file ${pkgs.lib.escapeShellArg adminFile} \
              sync-access --manifest "$manifest"${accessArgs} "$@"
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

          # Build the sync app. There is nothing to assert about the result --
          # the point is that `writeShellApplication` runs shellcheck and that
          # the two helper functions resolve at all, neither of which happens
          # anywhere else: `mkSyncApp` is a top-level function, so `nix flake
          # check` never reaches it, and the first consumer to call it is the
          # first thing to find out it does not evaluate.
          #
          # Which is how it went. Writing this cost one unbound variable
          # (`mkManifestApp` where `self.mkManifestApp` was meant -- the
          # function is an output attribute, not a `let` binding) and one
          # `mktemp` resolved off the caller's PATH rather than the closure.
          #
          # An empty fleet on purpose. The manifest's *content* is checked
          # above; this checks the script that carries it, and an empty one
          # builds the same script.
          sync-app = self.mkSyncApp {
            inherit pkgs;
            nixosConfigurations = { };
            url = "https://infisical.invalid";
            # Set, because the `ageKeyFile` block is the only conditionally
            # emitted shell in the app: left at its null default it renders to
            # the empty string, and a check that builds the app without it is a
            # check that shellcheck never reads the branch most likely to be
            # wrong. The value is a shell expression on purpose -- that is the
            # contract, and this is what exercises it.
            ageKeyFile = "\${XDG_CONFIG_HOME:-$HOME/.config}/sops/age/keys.txt";
          };

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
                  # Owned by the instance, not by SOPS. Identical in every
                  # other respect to the entries above -- which is the point:
                  # it is an ordinary manifest entry that `sync` declines to
                  # write the value of and `import` writes into SOPS. If the
                  # field ever stops reaching the manifest, `sync` starts
                  # pushing the local copy over the IdP's and the only symptom
                  # is an OIDC login that stops working.
                  "services/grafana/oidc_secret" = {
                    sopsFile = "/fleet/secrets/platform.yaml";
                    infisical = nixfisicalLib.mkInfisical {
                      project = "platform";
                      folder = "/grafana";
                      name = "OIDC_CLIENT_SECRET";
                      source = "infisical";
                    };
                  };
                  # Unannotated: must never appear in the manifest.
                  "internal/root_key" = { sopsFile = "/fleet/secrets/dbs.yaml"; };
                });
                beta = mkHost "beta" shared;
              };

              extraSecrets = [
                # No host declares this one, and none should: a mailbox
                # password is verified by the mail host as a hash and read in
                # plaintext only by a person. It must still land with the same
                # shape as every other entry, `hosts` empty.
                (nixfisicalLib.mkExportOnly {
                  sopsFile = "/fleet/secrets/mail-clients.yaml";
                  sopsKey = "mail.engine_password";
                  project = "platform";
                  folder = "/mail";
                })
                # Redundant with alpha+beta's annotation: same file, same key,
                # same destination. Must collapse into that one entry and leave
                # its host provenance intact, not append a second entry racing
                # it to the same coordinate.
                (nixfisicalLib.mkExportOnly {
                  sopsFile = "/fleet/secrets/api.yaml";
                  sopsKey = "services/api/token";
                  project = "apps";
                  folder = "/api";
                  groups = [ "developers" ];
                })
              ];

              manifest = nixfisicalLib.assertManifest
                (nixfisicalLib.manifestFrom {
                  nixosConfigurations = configurations;
                  inherit extraSecrets;
                });

              # Two entries aimed at one Infisical coordinate from different
              # files: nothing dedupes them, so `assertManifest` is the only
              # thing standing between a typo and a secret that silently loses.
              dupCaught = !(builtins.tryEval
                (builtins.deepSeq
                  (nixfisicalLib.assertManifest (nixfisicalLib.manifestFrom {
                    extraSecrets = [
                      (nixfisicalLib.mkExportOnly {
                        sopsFile = "/fleet/secrets/a.yaml";
                        sopsKey = "pw";
                        project = "platform";
                        name = "PW";
                      })
                      (nixfisicalLib.mkExportOnly {
                        sopsFile = "/fleet/secrets/b.yaml";
                        sopsKey = "other";
                        project = "platform";
                        name = "PW";
                      })
                    ];
                  }))
                  true)).success;

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
                  source = "sops";
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
                  source = "sops";
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
                  source = "sops";
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
                  source = "sops";
                }
                {
                  environment = "prod";
                  folder = "/mail";
                  groups = [ ];
                  hosts = [ ];
                  name = "mail.engine_password";
                  project = "platform";
                  sopsFile = "/fleet/secrets/mail-clients.yaml";
                  sopsKey = "mail.engine_password";
                  source = "sops";
                }
                # The one entry the instance owns. Its presence here is what
                # pins `source` to the manifest: drop the field from the
                # plumbing and this entry reads "sops" like every other one,
                # and `sync` starts overwriting a value it did not author.
                {
                  environment = "prod";
                  folder = "/grafana";
                  groups = [ ];
                  hosts = [ "alpha" ];
                  name = "OIDC_CLIENT_SECRET";
                  project = "platform";
                  sopsFile = "/fleet/secrets/platform.yaml";
                  sopsKey = "services/grafana/oidc_secret";
                  source = "infisical";
                }
              ];
            in
            if actual != expected then
              throw ''
                nixfisical manifest check failed.
                  expected: ${expected}
                  actual:   ${actual}
              ''
            else if !dupCaught then
              throw ''
                nixfisical manifest check failed: assertManifest accepted two
                entries declared into the same Infisical destination.
              ''
            else "echo ok > $out"
          );
        };

        formatter = pkgs.nixpkgs-fmt;
      });
}
