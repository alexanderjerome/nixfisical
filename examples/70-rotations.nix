# Secret rotations: 28 kinds of credential that Infisical changes for us.
#
# A rotation owns a credential at the provider and writes the current value
# back into the project as ordinary secrets. Something reads those secrets
# and gets whatever is valid now.
#
# The part that makes this actually work is the two-username pattern, which
# is worth understanding before declaring one. Infisical keeps TWO accounts
# and alternates: while `username1` is live, it rotates `username2`'s
# password; next interval it swaps. So there is always a credential that is
# valid and was valid a moment ago, and a consumer that cached the old value
# has an interval to notice. A single-account rotation has a window where
# everything holding the old password is broken, and that window is why
# rotation gets turned off everywhere it is naively implemented.
#
# THE TRAP for anything that prunes:
#
#   `secretsMapping` names keys that Infisical writes. Those keys are not in
#   the declaration — they cannot be, their values are unknown to us. A prune
#   pass sees undeclared keys and deletes them. On the next rotation
#   Infisical rewrites them, so the damage is invisible until something reads
#   a secret that is not there yet.
#
#   Mark them `unmanaged` (see 40-secrets.nix), or have the reconciler derive
#   the don't-touch set from every secretsMapping it can see. Do both.
{
  infisical.instances.lab.projects.apps.rotations = {

    # -- the shape ----------------------------------------------------------
    #
    # POST /api/v2/secret-rotations/{type}
    #
    # Required on all 28: name, projectId, connectionId, environment,
    # secretPath, rotationInterval, parameters, secretsMapping.

    app-db-credentials = {
      type = "postgres-credentials";

      # The credential Infisical uses to perform the rotation — an account
      # with rights to ALTER the two accounts below. Not one of them.
      connectionId = "lab-postgres";

      environment = "prod";
      secretPath = "/cli-proxy";
      description = "Alternating app DB accounts";

      # Days, minimum 1. The floor is a day, so this is not a mechanism for
      # short-lived credentials — that is dynamic secrets, 80-dynamic.
      rotationInterval = 30;

      # When in the day, UTC. Both hours (0-23) and minutes (0-59) are
      # REQUIRED if the object is given at all. Omit the object and the
      # server picks.
      rotateAtUtc = { hours = 3; minutes = 0; };

      # Default true. False means it only rotates when asked, via
      # POST .../{rotationId}/rotate-secrets.
      isAutoRotationEnabled = true;

      # Type-specific. For postgres-credentials this is where the two-account
      # pattern is declared: both usernames REQUIRED, and BOTH ACCOUNTS MUST
      # ALREADY EXIST. Infisical rotates passwords; it does not CREATE users.
      # Pointing this at a username that does not exist fails at rotation
      # time, not at declaration time.
      parameters = {
        username1 = "app_rw_a";
        username2 = "app_rw_b";

        # Optional SQL run after the password change — grants, search_path,
        # whatever the account needs re-asserted.
        rotationStatement = null;

        passwordRequirements = {
          length = 48;              # 1-250
          required = {
            digits = 2;
            lowercase = 2;
            uppercase = 2;
            symbols = 0;            # see below
          };
          allowedSymbols = "-_.~";
        };
        # Requiring symbols and then allowing a narrow set is how you
        # generate passwords that break a consumer's connection-string
        # parser six weeks later. Zero symbols and more length is the same
        # entropy and none of the escaping.
      };

      # Where the rotated values land. Both REQUIRED for this type.
      #
      # These two keys are now owned by Infisical. Declare them `unmanaged`
      # in 40-secrets.nix or lose them to a prune.
      secretsMapping = {
        username = "DB_USER";
        password = "DB_PASSWORD";
      };
    };

    # -- a single-credential rotation ----------------------------------------
    #
    # Not everything supports the alternating pattern. An API token at a SaaS
    # provider is usually one token, and rotating it means there is a moment
    # when the old one stops working. Those types take no username pair —
    # their `parameters` are provider-specific and their `secretsMapping` is
    # often a single key.
    #
    # Same object, much sharper edge. Anything caching the value needs to
    # re-read it promptly, which in practice means the consumer has to be
    # reading from Infisical at request time rather than at deploy time.
    cloudflare-token = {
      type = "cloudflare-api-token";
      connectionId = "lab-cloudflare";
      environment = "prod";
      secretPath = "/dns";
      rotationInterval = 90;
      parameters = { };
      secretsMapping.apiToken = "CLOUDFLARE_API_TOKEN";
    };
  };

  # -- non-CRUD operations --------------------------------------------------
  #
  #   POST .../{rotationId}/rotate-secrets         rotate now
  #   GET  .../{rotationId}/generated-credentials  read the current pair
  #   POST .../{type}/check-credentials            validate before creating
  #   POST .../{rotationId}/move                   relocate to another path
  #   GET  .../{type}/rotation-name/{name}         look up by name
  #
  # check-credentials is the useful one for a reconciler: it answers "would
  # this work" without creating anything, which makes a dry run meaningful
  # for the one object class where a failed create leaves a half-rotated
  # account.
  #
  # read-generated-credentials is a SEPARATE permission action from operating
  # the rotation. You can grant someone the ability to run a rotation without
  # the ability to see what it produced. See 30-project.nix.

  # -- the other 26 types ---------------------------------------------------
  #
  # auth0-client-secret aws-iam-user-secret azure-client-secret
  # cloudflare-api-token cloudflare-r2-access-key convex-access-key
  # databricks-service-principal-secret datadog-api-key
  # datadog-application-key-secret dbt-service-token fireworks-api-key
  # hp-ilo-local-account ldap-password litellm-api-key mongodb-credentials
  # mssql-credentials mysql-credentials okta-client-secret
  # open-router-api-key openai-service-account oracledb-credentials
  # postgres-credentials redis-credentials salesforce-oauth-credentials
  # snowflake-user-key-pair supabase-api-key unix-linux-local-account
  # windows-local-account
  #
  # unix-linux-local-account and windows-local-account are the ones to note
  # for a homelab: Infisical rotating the password of an actual OS account
  # over SSH or WinRM, via the ssh / winrm connections. That is a
  # configuration-management capability wearing a secrets-manager hat, and it
  # is the closest thing here to what fleetkit already does.
  #
  # Generated into nix/lib/generated/rotations.nix.
}
