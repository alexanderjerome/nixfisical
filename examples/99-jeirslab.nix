# What the lab actually runs, and what it becomes.
#
# Every other file here is a sketch of something that could be built. This
# one is measured against a running server (CT 120, infisical.jeirslab.xyz)
# and against the two declarations that exist in jeirslab today. If it
# disagrees with reality, this file is wrong, not reality.
#
# ============================================================================
# TODAY
# ============================================================================
#
# There is no `infisical.instances` option. What exists is an ANNOTATION on a
# sops secret, and it lives in the host that owns the secret:
#
#   # jeirslab fleet/hosts/cli-proxy.nix
#   sops.secrets."cli-proxy/api_key" = {
#     sopsFile = ../../secrets/cli-proxy.yaml;
#     key = "api_key";
#     owner = "cli-proxy";
#     infisical = nixfisical.lib.mkInfisical {
#       project = "apps";
#       folder = "/cli-proxy";
#       groups = [ "developers" ];
#       name = "CLI_PROXY_API_KEY";
#     };
#   };
#
#   # jeirslab fleet/hosts/infra-db.nix
#   "infra-db/mealie".infisical = nixfisical.lib.mkInfisical {
#     project = "databases";
#     folder = "/mealie";
#     groups = [ "developers" ];
#   };
#
# Two secrets. That is the entire production footprint of this tool.
#
# What is good about that shape and must survive: the annotation is OPT-IN
# PER SECRET. `cli-proxy/mgmt_key` sits directly beside `api_key` in the same
# file with the same owner and is NOT exported, because it reconfigures the
# proxy and can read back the Claude account token. `infra-db/mealie` is
# exported and its seven siblings are not. Read access to those is read
# access to the fleet.
#
# A file-level or host-level opt-in would have exported all of them. The
# per-secret granularity is the whole point and nothing below may lose it.
#
# ============================================================================
# WHAT THE ANNOTATION MODEL CANNOT SAY
# ============================================================================
#
# 1. Anything with no host. A project's environments, a role, a group, an app
#    connection, a rotation — none of these belong to a machine. Today they
#    are created by `nixfisical bootstrap` imperatively and drift silently.
#
# 2. `groups = [ "developers" ]` is a per-secret field that grants at PROJECT
#    scope. Name a group on ONE secret and it gets the whole project. The
#    option reads like it scopes access and it does not. 30-project.nix
#    replaces it with CASL conditions on environment and secretPath, which is
#    what it was always trying to be.
#
# 3. One environment. There is no way to say "this value in prod, that one in
#    dev", because a sops secret is one value.
#
# 4. Anything Infisical owns. A rotation's output, a dynamic secret — these
#    have no sops file to hang off.
#
# The two models are not in conflict. The annotation answers "this host's
# secret should also be in Infisical"; the declaration answers "this is what
# the server contains". Both are wanted. The annotation desugars into the
# declaration.
#
# ============================================================================
# WHAT IT BECOMES
# ============================================================================
{
  infisical.instances.jeirslab = {
    url = "https://infisical.jeirslab.xyz";
    organization.slug = "jeirslab";
    auth.sopsFile = ../../secrets/infisical.yaml;

    # First runs against a server that was bootstrapped imperatively should
    # be dry. The declaration below was written from the two call sites and
    # from what bootstrap happened to create — it has never been diffed
    # against the live server, and the first diff is the interesting one.
    settings.dryRun = true;

    projects = {

      # -- apps --------------------------------------------------------------
      apps = {
        projectName = "apps";
        slug = "apps";

        # MEASURED, not assumed: this project has dev/staging/prod on the
        # live server despite the manifest naming only prod. The cause is
        # `shouldCreateDefaultEnvs`, which defaults true and which the
        # current code does not pass — so Infisical seeded three and we
        # declared one.
        #
        # Declaring all three here is the honest move. Declaring only prod
        # and setting prune.environments = "soft" would delete two
        # environments on the next run, which is a real (recoverable)
        # deletion against a live server and not something to discover from
        # a reconcile summary.
        environments = {
          dev = { name = "Development"; position = 1; };
          staging = { name = "Staging"; position = 2; };
          prod = { name = "Production"; position = 3; };
        };

        folders."/cli-proxy" = {
          description = "CLIProxyAPI";
          environments = [ "prod" ];
        };

        secrets.prod."/cli-proxy" = {
          # The one real exported secret. Same sops file, same key, same
          # name as fleet/hosts/cli-proxy.nix declares today — this is that
          # annotation, moved.
          CLI_PROXY_API_KEY = {
            sopsFile = ../../secrets/cli-proxy.yaml;
            sopsKey = "api_key";
            secretComment = "Handed out in editor configs; rotate via the proxy";
          };
        };

        # `groups = [ "developers" ]` on the annotation became this. The
        # difference that matters: this grants read on ONE folder in ONE
        # environment, where the annotation granted the whole project.
        roles.cli-proxy-ro = {
          name = "CLI proxy read-only";
          permissions = [
            {
              subject = "secrets";
              action = [ "read" "readValue" ];
              conditions = {
                environment."$eq" = "prod";
                secretPath."$eq" = "/cli-proxy";
              };
            }
            { subject = "secret-folders"; action = "read";
              conditions.environment."$eq" = "prod"; }
          ];
        };

        membership.groups.developers.roles = [ "cli-proxy-ro" ];

        # NOT exported and must stay that way: cli-proxy/mgmt_key. It is in
        # secrets/cli-proxy.yaml next to api_key and it reconfigures the
        # proxy. Named here so that "why is this file only half the sops
        # file" has an answer in the file rather than in a commit message.
      };

      # -- databases ---------------------------------------------------------
      databases = {
        projectName = "databases";
        slug = "databases";

        # Same three-environment situation as apps, same cause.
        environments = {
          dev = { name = "Development"; position = 1; };
          staging = { name = "Staging"; position = 2; };
          prod = { name = "Production"; position = 3; };
        };

        folders."/mealie" = {
          description = "Mealie application DB role";
          environments = [ "prod" ];
        };

        secrets.prod."/mealie" = {
          # The annotation set no `name`, so it defaulted to the sops key's
          # last segment: "mealie". Preserved verbatim — renaming it here
          # would orphan the existing secret on the server and create a new
          # one, which a prune would then clean up into a gap.
          mealie = {
            sopsFile = ../../secrets/infra-db.yaml;
            sopsKey = "mealie";
            secretComment = "Postgres role password for the mealie app DB";
          };
        };

        roles.mealie-ro = {
          name = "Mealie DB read-only";
          permissions = [
            {
              subject = "secrets";
              action = [ "read" "readValue" ];
              conditions = {
                environment."$eq" = "prod";
                secretPath."$eq" = "/mealie";
              };
            }
          ];
        };

        membership.groups.developers.roles = [ "mealie-ro" ];

        # The seven sibling roles in secrets/infra-db.yaml stay unexported.
        # infra-db also holds the credential behind the fleet's own
        # forward-auth, and read access to that database is read access to
        # the fleet.
      };
    };

    # -- groups: the licence problem -----------------------------------------
    #
    # `developers` is referenced by both projects above and by both existing
    # annotations. Group creation is licence-gated: on an unlicensed
    # self-hosted instance getDefaultOnPremFeatures() returns groups:false
    # and rbac:false, and the UI cannot create one either.
    #
    # So this block, and every `membership.groups` reference above, may be
    # unsatisfiable on the instance they are written for. That is why
    # `onUnsupported = "warn"` is the default in 10-instance.nix — the
    # secrets still sync, the RBAC does not, and the run says so.
    #
    # CONFIRMED, against v0.165.8's getDefaultOnPremFeatures(): `groups` and
    # `rbac` are both false, so this is not a caveat, it is the situation. And
    # the second half of the guess above was right too — the per-path RBAC that
    # motivates replacing `groups = [ ... ]` needs `rbac`, so the annotation's
    # coarse project-wide behaviour was not a design error. It was the only
    # thing that worked.
    #
    # Which part of `rbac` bites is worth being precise about, because it is
    # narrower than "RBAC is off": it gates creating a custom role at all, and
    # assigning a custom role to a user, group or identity. The four roles
    # Infisical ships — admin, member, viewer, no-access — are ungated, and
    # upstream tells them apart the same way, by `isCustomRole`. That is why
    # `sync-access` grants work on this instance and why its default is
    # `viewer`. The `cli-proxy-ro` and `mealie-ro` roles above are custom, so
    # they are the part that will not exist.
    #
    # Meanwhile `permission-service.ts` resolves group-derived permissions
    # without consulting the licence at all. Upstream gates the mutation, not
    # the evaluation — which is why `sync-access --create-missing-groups` can
    # write the rows directly and the running server honours them.
    organization.groups.developers = {
      name = "Developers";
      role = "member";
    };

    # -- nothing else -------------------------------------------------------
    #
    # No connections, no syncs, no rotations, no dynamic secrets, no PKI, no
    # KMS, no gateways. Files 50 through 93 describe roughly a thousand of
    # the API's 1479 paths and the lab uses none of them.
    #
    # The nearest thing to a real candidate was a gateway: infra-db and
    # tofu-db are on a private VLAN, and a gateway is what would let
    # Infisical rotate their passwords rather than us minting them with
    # `nixfisical secrets gen` and committing the ciphertext.
    #
    # Except a gateway needs `plan.gateway`, refused at the handshake, and
    # rotation needs `plan.secretRotation`. Both false here. So the whole
    # candidate is off the table on this instance, and `secrets gen` writing
    # into SOPS is not the stopgap before the good version — for an unlicensed
    # self-hosted instance it *is* the version. Worth knowing before spending
    # an evening on the gateway.
    #
    # What the licence leaves is most of what the lab uses: projects,
    # environments, folders, secrets, the sync itself, secret versioning
    # (which is on without a licence), built-in role grants, and a second
    # organization via `add-org`. The declaration model for the two secrets
    # that exist was always the thing in front; now it is also the thing
    # that can be built.
  };
}
