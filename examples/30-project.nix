# Project scope: settings, environments, folders, tags, RBAC.
#
# The project is the unit of access. Everything below it — environments,
# folders, secrets — is addressing, not isolation. If two things must not see
# each other, they are two projects, or two organizations.
#
# One structural wart worth knowing before you read: the project object is
# split across two calls. POST /api/v1/projects takes the creation fields and
# PATCH /api/v1/projects/{projectId} takes a different, larger set. The split
# below is the API's, mirrored rather than papered over, so that "why is this
# under settings" has an answer.
{
  infisical.instances.lab.projects.apps = {
    # -- create-time ---------------------------------------------------------
    #
    # POST /api/v1/projects
    projectName = "apps";
    projectDescription = "Host-facing application secrets";

    # Optional on create and settable on update. Omitting it gets you a
    # server-assigned slug with a random suffix, which is why the
    # organizations bootstrapped by hand are called things like
    # `xg-capital-strategies-6-ec-e`. Organizations cannot choose; projects
    # can. Choose.
    slug = "apps";

    type = "secret-manager"; # |cert-manager|kms|secret-scanning|pam

    # Naming an organization template applies its environments and roles.
    # null means no template, and the reconciler passes
    # shouldCreateDefaultEnvs = false so that the environments declared below
    # are the only ones that exist.
    #
    # These are one decision, not two: the server ignores
    # shouldCreateDefaultEnvs whenever a non-default template resolves. It is
    # never exposed as its own option for that reason.
    template = null;

    # Refuses project deletion until turned off. A one-way door in practice —
    # turning it off to delete is a deliberate act, which is the point.
    hasDeleteProtection = true;

    # Bring your own KMS key for the project's secret encryption. See
    # 91-kms.nix. Null uses the instance default.
    kmsKeyId = null;

    # -- update-time ---------------------------------------------------------
    #
    # PATCH /api/v1/projects/{projectId}. None of these can be set at create,
    # so the reconciler does create-then-patch. Grouped here to make that
    # visible rather than to hide it.
    settings = {
      # Upper-cases secret keys on write. On by default server-side, and it
      # will silently rewrite a key you declared in lower case.
      autoCapitalization = false;

      # Point-in-time snapshots retained. Snapshots are how you undo a bad
      # reconcile, so this is the blast-radius setting for this tool.
      pitVersionLimit = 10;

      # Self-hosted and dedicated only, and capped by the licence's retention
      # period. Rejected on cloud.
      auditLogsRetentionDays = 30;

      # The share-a-secret-by-link feature, per project.
      secretSharing = false;

      # Requires secret metadata to be stored encrypted. One-way in spirit:
      # turning it on re-encrypts, turning it off does not undo that.
      enforceEncryptedSecretManagerSecretMetadata = true;

      showSnapshotsLegacy = false;

      # Values the secret scanner should not flag. See 91-kms.nix for the
      # scanning surface proper; this field lives on the project.
      secretDetectionIgnoreValues = [ "example" "changeme" ];
    };

    # -- environments --------------------------------------------------------
    #
    # POST /api/v1/projects/{projectId}/environments  { name, slug, position }
    #
    # The attribute name is the slug — the thing every other call addresses
    # by. `name` is the display string and `position` orders the UI columns.
    #
    # Deletion is SOFT by default, with ?hardDelete=true and a
    # POST .../environments/{id}/restore. That is what makes pruning
    # environments a reasonable default rather than a dangerous one.
    environments = {
      dev = { name = "Development"; position = 1; };
      staging = { name = "Staging"; position = 2; };
      prod = { name = "Production"; position = 3; };
    };

    # -- folders -------------------------------------------------------------
    #
    # POST /api/v2/folders  { projectId, environment, name, path, description }
    #
    # Folders exist per environment. Declaring them here rather than per
    # environment is a deliberate flattening: in practice the same tree is
    # wanted in every environment, and the reconciler expands across the
    # environments declared above. Override with `environments` on the entry
    # when that is wrong.
    #
    # Note `path` is the PARENT and `name` is the leaf. Whether v2 creates
    # missing ancestors is unverified — the v1 comment in api.py claims there
    # is no mkdir -p, and that claim predates v2.
    folders = {
      "/cli-proxy" = { description = "CLI proxy service"; };
      "/mealie" = { description = "Recipe manager"; };
      "/ci" = { description = "Shared CI credentials"; environments = [ "prod" ]; };
    };

    # -- tags ----------------------------------------------------------------
    #
    # POST /api/v1/projects/{projectId}/tags  { slug, color }
    #
    # `color` is REQUIRED, which is easy to miss. Writes take tagIds (UUIDs)
    # and filters take tagSlugs, so the reconciler resolves slug -> id on
    # every secret write that carries tags.
    tags = {
      rotate-me.color = "#e11d48";
      generated.color = "#0ea5e9";
      legacy.color = "#a1a1aa";
    };

    # -- project roles -------------------------------------------------------
    #
    # POST /api/v1/projects/{projectId}/roles
    #
    # This is where the CASL grammar pays for itself. At project scope the
    # `secrets` subject takes conditions on environment, secretPath,
    # secretName and secretTags, with $eq / $ne / $in / $glob (and $all /
    # $elemMatch for tags and metadata).
    #
    # Per-path RBAC is a strictly better answer than the per-secret `groups`
    # list the current export layer carries, where a group named on any one
    # entry silently gets the whole project.
    roles = {
      cli-proxy-ro = {
        name = "CLI proxy read-only";
        description = "Read one folder in one environment";
        permissions = [
          {
            subject = "secrets";
            # read = see that it exists; readValue = see the value. They are
            # separate actions, which is how you grant an inventory without
            # granting the contents.
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

      deployer = {
        name = "Deployer";
        permissions = [
          {
            subject = "secrets";
            action = [ "read" "readValue" "create" "edit" ];
            conditions = {
              environment."$in" = [ "dev" "staging" ];
              secretPath."$glob" = "/apps/**";
            };
          }
          # Deny by tag, overriding the grant above. `inverted` is how CASL
          # spells a deny rule, and deny wins.
          {
            subject = "secrets";
            action = "readValue";
            inverted = true;
            conditions.secretTags."$in" = [ "legacy" ];
          }
          { subject = "secret-imports"; action = "read"; }
          { subject = "secret-rollback"; action = [ "read" "create" ]; }
        ];
      };

      rotator = {
        name = "Rotation operator";
        permissions = [
          { subject = "secret-rotation";
            action = [ "read" "create" "edit" "rotate-secrets" ];
            conditions.environment."$eq" = "prod"; }
          # Reading the generated credentials is its own action, separate
          # from operating the rotation.
          { subject = "secret-rotation"; action = "read-generated-credentials";
            inverted = true; }
        ];
      };
    };

    # -- who holds those roles -----------------------------------------------
    #
    # Groups:     POST /api/v1/projects/{projectId}/memberships/groups/{groupId}
    # Identities: POST /api/v1/projects/{projectId}/memberships/identities/{identityId}
    # Users:      POST /api/v1/projects/{projectId}/memberships
    #
    # The older /projects/{id}/groups/* routes are marked deprecated in the
    # spec itself in favour of these.
    membership = {
      groups.developers.roles = [ "cli-proxy-ro" ];

      identities.fleet-sync.roles = [ "admin" ];

      users."ops@example.com".roles = [
        "viewer"
        # Time-boxed grants are first class. temporaryMode is "relative" —
        # the only value the spec offers — and temporaryRange is a duration
        # counted from temporaryAccessStartTime.
        {
          role = "admin";
          isTemporary = true;
          temporaryMode = "relative";
          temporaryRange = "2h";
          temporaryAccessStartTime = "2026-09-11T00:00:00Z";
        }
      ];
    };

    # -- event subscriptions -------------------------------------------------
    #
    # POST /api/v1/events/subscribe/project-events
    #
    # The only webhook-shaped thing in the whole API. Four events, filtered
    # by folder and environment.
    events = [
      {
        event = "secret:update"; # |secret:create|secret:delete|secret:import-mutation
        conditions = { secretPath = "/cli-proxy"; environmentSlug = "prod"; };
      }
    ];
  };
}
