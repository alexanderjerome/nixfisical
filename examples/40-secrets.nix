# Static secrets, imports, and what pruning is allowed to delete.
#
# The nesting is `secrets.<environment>."<folder>".<KEY>` because that is the
# shape of the call that writes them:
#
#   PATCH /api/v4/secrets/batch
#     { projectId, environment, mode, secrets: [ { secretKey, secretPath, ... } ] }
#
# One call per (project, environment). `secretPath` is per item, so one call
# covers many folders. Nothing crosses an environment. Matching the nesting
# to the call boundary means the reconciler batches by construction instead
# of by cleverness.
{
  infisical.instances.lab.projects.apps = {

    secrets.prod = {
      "/cli-proxy" = {
        # -- the ordinary case ---------------------------------------------
        CLI_PROXY_API_KEY = {
          sopsFile = ./secrets/cli-proxy.yaml;
          # Defaults to the attribute name lower-cased? No — it defaults to
          # the attribute name verbatim. Say so when they differ.
          sopsKey = "api_key";

          secretComment = "Rotated with the proxy deploy";

          # Slugs. Resolved to tagIds before the write, because writes take
          # UUIDs and only filters take slugs.
          tags = [ "rotate-me" ];

          # secretMetadata[] on the wire: a list of {key, value, isEncrypted}.
          # An attrset here, expanded by the reconciler. Distinct from the
          # legacy flat `metadata` map, which is different storage — do not
          # conflate them.
          secretMetadata = {
            owner = { value = "lab"; };
            ticket = { value = "INFRA-263"; };
            note = { value = "sensitive"; isEncrypted = true; };
          };

          # An email reminder, not a rotation. It nags a human; it does not
          # change the value. Real rotation is 70-rotations.nix.
          secretReminderNote = "Confirm the upstream key is still valid";
          secretReminderRepeatDays = 90;

          # The value is trimmed server-side on every write: leading
          # whitespace is destroyed and at most one trailing newline
          # survives. Values do not round-trip byte-exact. This flag is the
          # lever for multi-line values that must survive intact.
          skipMultilineEncoding = false;

          # "shared" (default) or "personal". A personal secret is an
          # override visible only to its author — meaningful for a human in
          # the UI, never for a declaration. Here for completeness only.
          type = "shared";
        };

        # -- not actually a secret -------------------------------------------
        #
        # A large share of what lives in Infisical is configuration. A
        # literal lands in the Nix store world-readable, which is correct
        # here and catastrophic one line up. That is why the option is named
        # `value` and not shared with `valueFrom`.
        CLI_PROXY_UPSTREAM.value = "https://api.anthropic.com";
        CLI_PROXY_TIMEOUT.value = "30";

        # -- a server-side reference ------------------------------------------
        #
        # Infisical expands ${...} at read time, against the pattern
        # [a-zA-Z0-9-_.@]. Four forms:
        #
        #   ${KEY}                            same folder
        #   ${prod.KEY}                       another environment, root
        #   ${prod.database.KEY}              another environment and folder
        #   ${@other-project.prod.db.KEY}     another project entirely
        #
        # Depth limit 10. An unresolvable same-project reference leaves the
        # literal ${...} in the value rather than erroring, so a typo here
        # ships a broken connection string rather than failing the run.
        CLI_PROXY_DSN.value =
          "postgres://\${DB_USER}:\${DB_PASSWORD}@\${prod.infra.DB_HOST}:5432/proxy";

        # -- owned by something else -------------------------------------------
        #
        # These two are written by the rotation in 70-rotations.nix. Without
        # `unmanaged` a prune pass would see undeclared keys and delete the
        # rotation's output on the next run.
        #
        # The reconciler can derive this set from every rotation's
        # secretsMapping and every dynamic secret's name. The explicit flag
        # is for the cases derivation cannot see: keys pulled in by a sync's
        # import-secrets, by a replicating import, or by a human in the UI
        # whose edit you have decided to tolerate.
        DB_USER.unmanaged = true;
        DB_PASSWORD.unmanaged = true;
      };

      # -- the general value form ----------------------------------------------
      #
      # sopsFile/sopsKey above is sugar over this. Any program satisfying the
      # resolver contract — descriptor as JSON on stdin, raw value on stdout —
      # slots in here without the schema changing.
      "/vault-sourced" = {
        LEGACY_TOKEN.valueFrom = {
          resolver = "vault";
          path = "kv/data/apps";
          field = "legacy_token";
        };
        FROM_PASSWORD_STORE.valueFrom = {
          resolver = "pass";
          entry = "lab/apps/token";
        };
      };
    };

    # Environments fan out by restating the folder. There is no
    # `perEnvironment` shorthand, deliberately: the prior art for it in the
    # archived infisical-sync-container declared `envs[]` plural and then
    # took envs[0], which is what a feature nobody wanted looks like.
    #
    # When one environment genuinely should be seeded from another, the API
    # has POST /api/v4/secrets/duplicate with per-attribute control.
    secrets.dev."/cli-proxy" = {
      CLI_PROXY_API_KEY.sopsFile = ./secrets/cli-proxy-dev.yaml;
      CLI_PROXY_UPSTREAM.value = "https://api.anthropic.com";
    };

    # -- imports -----------------------------------------------------------
    #
    # POST /api/v2/secret-imports
    #
    # A link, not a copy: the destination folder resolves the source's
    # secrets at read time. `sourceProjectId` omitted means the same project.
    #
    # isReplication = true changes the nature of the thing — secrets are
    # actively pushed to the destination rather than resolved through it, and
    # where an approval policy exists at the destination they arrive as
    # approval requests. Replicated keys are keys we do not own; see
    # `unmanaged` above.
    imports = [
      {
        environment = "prod";
        path = "/cli-proxy";
        import = { environment = "prod"; path = "/shared"; };
        isReplication = false;
      }
      {
        environment = "prod";
        path = "/vendor";
        import = {
          sourceProject = "platform"; # resolved to sourceProjectId
          environment = "prod";
          path = "/exports";
        };
        isReplication = true;
      }
    ];

    # -- one-shot moves ------------------------------------------------------
    #
    # POST /api/v4/secrets/move and POST /api/v2/folders/move.
    #
    # These are migrations, not desired state — running them twice is not the
    # same as running them once. Declaring them at all is arguable. If they
    # stay, they need a ledger so a completed move is not re-attempted, which
    # is state this tool does not otherwise keep.
    #
    # Left here as a marker that the capability exists, not as a proposal.
    #
    # moves = [ { from = { environment = "dev"; secretPath = "/old"; };
    #             to   = { environment = "dev"; secretPath = "/new"; }; } ];

    # -- pruning -------------------------------------------------------------
    #
    # What the reconciler may delete when the server has something the
    # declaration does not.
    #
    #   off     leave it, say nothing
    #   report  leave it, name it in the run summary
    #   soft    delete recoverably where the API offers that
    #   hard    delete permanently
    #
    # Environments support soft properly: DELETE is soft by default with
    # ?hardDelete=true and a /restore endpoint. Secrets have version history
    # and project snapshots (pitVersionLimit) behind them, so "soft" there
    # means relying on those. Folders have neither, which is why the default
    # below is not symmetric.
    prune = {
      environments = "soft";
      secrets = "report";
      folders = "off";
      tags = "report";
      roles = "report";
    };
  };
}
