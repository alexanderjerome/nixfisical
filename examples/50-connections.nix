# App connections: 84 kinds of "here is how to reach that thing".
#
# This is the spine of the outbound half of Infisical. A secret sync, a
# rotation and most dynamic secret providers all take a `connectionId`, and
# none of them can be declared without one. If you only ever push SOPS into
# Infisical you will never create a connection; the moment you want Infisical
# to do anything for you, it is the first object.
#
# Connections are PROJECT-scoped — `projectId` is on the create body — even
# though the permission subject `app-connections` lives at organization
# scope. That split is real and occasionally surprising.
#
# Credentials travel plaintext in the POST/PATCH body. Responses mask them and
# return a `credentialsHash` instead. Two consequences:
#
#   - The reconciler cannot diff credentials. It can compare the hash if it
#     knows the algorithm, or it can write unconditionally. There is no third
#     option.
#   - A connection credential is a secret that never lands on a host. It
#     needs the same SOPS discipline as anything else and it is NOT a
#     sops.secrets entry — nothing on the machine reads it but the
#     reconciler, once, at reconcile time.
{
  infisical.instances.lab.projects.apps.connections = {

    # -- the shape ----------------------------------------------------------
    #
    # POST /api/v1/app-connections/{kind}
    #
    # Every kind shares an envelope and then diverges into a
    # method + credentials union. The envelope:
    #
    #   name                          REQUIRED, 1-64
    #   projectId                     REQUIRED (supplied by nesting)
    #   description                   max 256
    #   gatewayId / gatewayPoolId     route through a gateway
    #   isPlatformManagedCredentials  see below
    #   isAutoRotationEnabled         see below
    #   rotation                      see below
    #
    # The attribute name is the connection's `name`. Everything that refers
    # to a connection refers to it by that name, and the reconciler resolves
    # the UUID.

    lab-postgres = {
      kind = "postgres";
      description = "Primary application database";

      # The union. `method` selects the branch and `credentials` is that
      # branch's field set — not a blob. postgres has one method; aws has
      # two (assume-role, access-key); github has several.
      method = "username-and-password";

      # Per-field, not a single credentialsFile, because only one of these
      # is a secret. A file-shaped option would force the hostname and the
      # port into SOPS along with the password, and then the hostname is
      # invisible in review for no reason.
      #
      # It also lines up with generating this: the option set for a kind is
      # exactly `attrsOf secretSource` over that kind's credential fields,
      # which is mechanical.
      #
      # REQUIRED for postgres: host, port, database, username, password,
      # sslEnabled, sslRejectUnauthorized. The two ssl booleans being
      # required rather than defaulted is unusual and easy to trip over.
      credentials = {
        host.value = "db.internal";
        port.value = 5432;
        database.value = "app";
        username.value = "infisical";
        password.sopsFile = ./secrets/pg.yaml;
        sslEnabled.value = true;
        sslRejectUnauthorized.value = true;
        sslCertificate = null;
      };

      # -- platform-managed credentials --------------------------------------
      #
      # Infisical takes ownership of this connection's own password: it
      # rotates it on a schedule and we stop knowing what it is.
      #
      # Available on exactly FOUR of the 84 kinds — postgres, mysql, mssql,
      # oracledb — and that is not arbitrary. Infisical can only take
      # ownership of a credential it can change, and a SQL database is where
      # it can issue the ALTER USER itself.
      #
      # "Once enabled this cannot be reversed", per the spec's own
      # description. There is no PATCH back to false. Turning this on is a
      # one-way door, and if the reconciler's copy of the password is what
      # you were relying on to get in, you have just lost it.
      #
      # Which is the point — nobody holds it — but it has to be a decision.
      isPlatformManagedCredentials = false;

      # Route the connection through a gateway. A database on a private VLAN
      # is the motivating case, and the usual one in a homelab.
      gatewayId = "lab-lan";
    };

    # -- connection credential rotation --------------------------------------
    #
    # Distinct from both platform-managed credentials above and from the
    # secret rotations in 70-rotations.nix:
    #
    #   platform-managed   Infisical owns the credential, nobody sees it
    #   connection rotation  the connection's own credential is re-issued
    #                        against the provider on a schedule
    #   secret rotation      a secret IN a project is rotated and written
    #                        back as project secrets
    #
    # Available on SEVEN kinds, and they are the seven where the provider
    # exposes an API to re-issue the credential in place: the five Azure
    # kinds (key-vault, app-configuration, client-secrets, devops, dns),
    # azure-entra-id, and ldap.
    corp-ldap = {
      kind = "ldap";
      method = "simple-bind";
      credentials = {
        provider.value = "active-directory"; # the only enum value
        url.value = "ldaps://dc.internal";
        dn.value = "cn=infisical,ou=svc,dc=example,dc=com";
        password.sopsFile = ./secrets/ldap.yaml;
        sslRejectUnauthorized.value = true;
        sslCertificate = null;
      };

      isAutoRotationEnabled = true;
      rotation = {
        rotationInterval = 30;             # days, 1-365, REQUIRED
        rotateAtUtc = { hours = 3; minutes = 0; }; # both REQUIRED
      };

      gatewayId = "lab-lan";
    };

    # -- a cloud connection, for contrast ------------------------------------
    #
    # Two methods. assume-role is the one to use when Infisical runs in AWS,
    # because there is then no long-lived credential at all.
    prod-aws = {
      kind = "aws";
      method = "assume-role";              # | "access-key"
      credentials = {
        roleArn.value = "arn:aws:iam::123456789012:role/infisical";
        stsEndpoint.value = "https://sts.amazonaws.com/";
      };
      # access-key branch: { accessKeyId, secretAccessKey } both REQUIRED.
    };

    # -- instance-to-instance ------------------------------------------------
    #
    # The connection that makes 93-federation.nix possible: one Infisical
    # authenticating to another as a machine identity. One method only.
    #
    # This kind forbids gatewayId, gatewayPoolId, rotation and
    # platform-managed credentials outright — their schemas are `not {}`,
    # which is the spec's way of saying the field exists and no value is
    # acceptable.
    upstream = {
      kind = "external-infisical";
      method = "machine-identity-universal-auth";
      credentials = {
        instanceUrl.value = "https://infisical.upstream.example.com"; # max 512
        machineIdentityClientId.value = "…uuid…";
        machineIdentityClientSecret.sopsFile = ./secrets/upstream.yaml; # max 512
      };
    };
  };

  # -- the other 80 kinds --------------------------------------------------
  #
  # 1password adcs anthropic auth0 aws azure-adcs azure-app-configuration
  # azure-client-secrets azure-devops azure-dns azure-entra-id
  # azure-key-vault bitbucket camunda checkly chef circleci cloud-66
  # cloudflare convex databricks datadog daytona dbt devin digicert
  # digital-ocean dns-made-easy doppler external-infisical f5-big-ip
  # fireworks flyio gcp github github-radar gitlab godaddy hashicorp-vault
  # hasura-cloud heroku humanitec kemp-loadmaster laravel-forge ldap litellm
  # microsoft-intune mongodb mssql mysql netlify netscaler northflank
  # nutanix-prism-central oci octopus-deploy okta ona open-router openai
  # oracledb ovh postgres qovery railway redis render rundeck salesforce smb
  # snowflake spacelift ssh supabase teamcity terraform-cloud travis-ci
  # trigger-dev venafi venafi-tpp vercel windmill winrm zabbix
  #
  # (There is also an `/options` path under the same prefix. It is a metadata
  # endpoint listing what is available — not an 85th kind. Same trap exists
  # under secret-syncs and secret-rotations, which is why the counts here are
  # 84/49/28 and not 85/50/29.)
  #
  # Each has its own inlined credential schema. None of these is written by
  # hand: the option set per kind is generated from the spec into
  # nix/lib/generated/connections.nix and checked in. Hand-writing ten of
  # them guarantees the eleventh is a rewrite, and there are eighty.
}
