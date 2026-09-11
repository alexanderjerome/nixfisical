# Dynamic secrets: credentials that do not exist until something asks.
#
# The difference from a rotation (70-rotations.nix) is not the interval, it
# is the ownership. A rotation keeps a credential alive and changes it
# periodically; the credential exists between rotations and is stored as a
# project secret. A dynamic secret creates a credential on request, hands it
# over with a TTL, and destroys it when the lease expires. Between requests
# there is nothing to steal.
#
# TWO STRUCTURAL ODDITIES, both of which will bite a reconciler:
#
#   1. These routes address by SLUG, not by id. `projectSlug` and
#      `environmentSlug` — the only place in the API that does this.
#      Everything else takes projectId. A reconciler that has resolved ids
#      everywhere has to keep the slugs around for exactly this call.
#
#   2. A dynamic secret occupies a name in a folder, the same namespace as a
#      static secret, and its name will show up in a listing. Prune will want
#      to delete it. Same problem as secretsMapping in 70-rotations.nix, same
#      answer: derive the don't-touch set, and mark it `unmanaged`.
{
  infisical.instances.lab.projects.apps.dynamicSecrets = {

    # -- the shape ----------------------------------------------------------
    #
    # POST /api/v1/dynamic-secrets
    #
    # Required: projectSlug, environmentSlug, name, defaultTTL, provider.

    app-db-session = {
      environmentSlug = "prod";
      path = "/cli-proxy";     # default "/"

      # A duration STRING, not a number — "1h", "30m", "7d". Required.
      # "The default TTL that will be applied for all the leases", per the
      # spec, so a lease may ask for less.
      defaultTTL = "1h";

      # Nullable string. The ceiling a lease may request. Null means the
      # request decides, which for a credential that grants database access
      # means the requester decides how long their own access lasts. Set it.
      maxTTL = "8h";

      # How the generated account is named. Max 255. Worth setting so that a
      # connection sitting in pg_stat_activity is traceable back to who
      # leased it — an unnamed dynamic credential is an audit gap that only
      # shows up during an incident.
      usernameTemplate = "inf_{{identity.name}}_{{random}}";

      metadata = {
        owner = "lab";
        purpose = "cli-proxy request-time DB access";
      };

      # 27 providers, each with its own inlined schema. The attribute set
      # below is that provider's fields, not a blob.
      provider = {
        type = "sql-database";
        client = "postgres";        # postgres | mysql | mssql | oracledb ...
        host = "db.internal";
        port = 5432;
        database = "app";

        # The admin credential Infisical uses to CREATE and DROP the
        # ephemeral accounts. This is the most privileged credential in this
        # whole directory — it can make users — and it is the reason dynamic
        # secrets are a bigger grant than they look.
        username = "infisical_admin";
        password.sopsFile = ./secrets/pg-admin.yaml;

        # The SQL that runs on lease creation and expiry. This is where the
        # actual grant is decided; the provider only supplies the account.
        # Getting revocationStatement wrong leaks accounts silently — they
        # accumulate, they keep their grants, and nothing reports it.
        creationStatement = ''
          CREATE ROLE "{{username}}" WITH LOGIN PASSWORD '{{password}}'
            VALID UNTIL '{{expiration}}';
          GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{username}}";
        '';
        revocationStatement = ''
          REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{{username}}";
          DROP ROLE "{{username}}";
        '';
        renewStatement = ''
          ALTER ROLE "{{username}}" VALID UNTIL '{{expiration}}';
        '';

        ca = null;
        gatewayId = "lab-lan";
      };
    };

    # -- a provider with no external system ----------------------------------
    #
    # totp is the odd one: it generates a TOTP code from a stored seed. There
    # is nothing to create or destroy at a provider, so there is no admin
    # credential and no statements — it is a calculator with an audit log.
    # Useful when a human process needs a second factor that is shared but
    # not screenshotted into a group chat.
    shared-mfa = {
      environmentSlug = "prod";
      path = "/ops";
      defaultTTL = "5m";
      provider = {
        type = "totp";
        secret.sopsFile = ./secrets/totp.yaml;
        period = 30;
        digits = 6;
        algorithm = "sha1";
      };
    };

    # See 92-kubernetes.nix for the kubernetes provider, which is the one
    # with two genuinely different oneOf branches (static vs dynamic
    # credentialType) rather than one shape with optional fields.
  };

  # -- leases ---------------------------------------------------------------
  #
  #   POST   /api/v1/dynamic-secrets/leases              create
  #   GET    /api/v1/dynamic-secrets/leases/{leaseId}    inspect
  #   POST   .../leases/{leaseId}/renew                  extend
  #   DELETE /api/v1/dynamic-secrets/leases/{leaseId}    revoke early
  #
  # Not declarable, and that is not an omission. A lease is a running thing
  # with an expiry; a declaration says what should be true, not what is. A
  # declared lease would be a lease that a reconcile run keeps resurrecting.
  #
  # The `config` object on lease create is empty for every provider except
  # kubernetes, which accepts a `namespace` override.
  #
  # The consequence for pruning, which is not obvious: deleting a dynamic
  # secret revokes every live lease under it. That is a running workload
  # losing its database connection, not a configuration object disappearing.
  # Whatever `prune.dynamicSecrets` ends up defaulting to, it should not be
  # "hard", and the run summary should say how many live leases a deletion
  # would take with it.

  # -- the other 25 providers -----------------------------------------------
  #
  # sql-database clickhouse cassandra sap-ase aws-iam redis sap-hana
  # aws-elasticache aws-memorydb mongo-db-atlas elastic-search mongo-db
  # rabbit-mq azure-entra-id azure-sql-database ldap snowflake totp
  # kubernetes vertica gcp-iam github couchbase milvus ssh ibm-api-connect
  # tailscale
  #
  # `ssh` is the interesting one for a homelab: Infisical issues a
  # short-lived SSH credential rather than a database account. That is the
  # same problem fleetkit solves with keys in SOPS, solved the other way —
  # nothing persistent to distribute and nothing to revoke by hand.
  #
  # Generated into nix/lib/generated/dynamic-secrets.nix.
}
