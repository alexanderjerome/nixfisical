# Organization scope.
#
# Everything here is shared by every project in the organization: roles,
# groups, machine identities, and the templates that let you stamp out a
# project without restating its environments and roles each time.
#
# The organization is the security boundary. A machine identity belongs to
# one and cannot enumerate another's projects. Two estates sharing one server
# share the server and nothing else.
{
  infisical.instances.lab.organization = {
    # SELECTION, not declaration. These three pick which organization on the
    # instance this block governs — tried in the order id, slug, name — and
    # every other attribute below describes what it should contain.
    #
    # They are selectors rather than settings because an organization cannot
    # be created through this API and cannot choose its own slug: the server
    # generates one with a random suffix at signup. `slug` here matches; it
    # does not set.
    id = null;
    slug = "lab";
    name = null;

    # -- roles ---------------------------------------------------------------
    #
    # POST /api/v1/organization/roles
    #
    # Permissions are a CASL grammar, not a role name: a list of
    # { subject, action, inverted?, conditions? }. The subject enum at
    # organization scope has 33 members; `action` is subject-dependent and is
    # either one string or a list of them.
    #
    # Only `app-connections` carries `conditions` at organization scope —
    # every other subject is unconditional. Project scope is where the
    # conditional grammar earns its keep; see 30-project.nix.
    roles = {
      auditor = {
        name = "Auditor";
        description = "Read the ledger, touch nothing";
        permissions = [
          { subject = "audit-logs"; action = "read"; }
          { subject = "project"; action = "read"; }
          { subject = "settings"; action = "read"; }
        ];
      };

      connection-operator = {
        name = "Connection operator";
        permissions = [
          {
            subject = "app-connections";
            action = [ "read" "connect" "rotate-credentials" ];
            # The one conditional subject at this scope.
            conditions.connectionId."$in" = [ "…uuid…" "…uuid…" ];
          }
          {
            subject = "app-connections";
            action = "delete";
            inverted = true; # explicit deny
          }
        ];
      };

      # The escape hatch that is not a role: `organization-admin-console`
      # with `access-all-projects`. Grants sight of every project in the
      # organization regardless of membership. Declare it only on purpose.
      break-glass = {
        name = "Break glass";
        permissions = [
          { subject = "organization-admin-console"; action = "access-all-projects"; }
        ];
      };
    };

    # -- groups --------------------------------------------------------------
    #
    # POST /api/v1/groups  { name, slug, role }
    #
    # `role` is the organization-level role, default "no-access". Project
    # access is granted separately, per project — see 30-project.nix.
    #
    # Group creation is licence-gated. On an unlicensed self-hosted instance
    # getDefaultOnPremFeatures() returns groups:false and rbac:false, and the
    # UI cannot create one either. The reconciler must degrade — warn and
    # skip — rather than abort a whole run because of a feature the server
    # does not have.
    groups = {
      developers = {
        name = "Developers";
        role = "member";
      };
      robots = {
        name = "Robots";
        role = "no-access";
      };
    };

    # -- machine identities --------------------------------------------------
    #
    # POST /api/v1/identities  { name, organizationId, role, hasDeleteProtection, metadata[] }
    #
    # then an auth method is attached at
    # POST /api/v1/auth/{method}-auth/identities/{identityId}
    #
    # Twelve auth methods exist: universal, token, aws, azure, gcp, alicloud,
    # oci, jwt, oidc, ldap, kubernetes, tls-cert, spiffe. Only universal-auth
    # has a rich parameter set; the rest are mostly trust configuration.
    identities = {
      # The identity the reconciler itself uses.
      fleet-sync = {
        role = "admin";
        hasDeleteProtection = true;
        metadata = { estate = "lab"; purpose = "reconcile"; };

        auth.universal = {
          # Seconds. Both default to 2592000 (30 days).
          accessTokenTTL = 3600;
          accessTokenMaxTTL = 86400;

          # 0 means unlimited. A sync run uses one token for many calls, so
          # a use limit is a footgun unless you know the call count.
          accessTokenNumUsesLimit = 0;

          # 0 disables periodic tokens.
          accessTokenPeriod = 0;

          # Both default to [ "0.0.0.0/0" "::/0" ] — i.e. open. Narrowing
          # these is the cheapest real hardening available on this object.
          clientSecretTrustedIps = [ "10.1.1.0/24" ];
          accessTokenTrustedIps = [ "10.1.1.0/24" ];

          # Defaults: enabled, threshold 3 (1-30), duration 300s (30-86400),
          # counter reset 30s (5-3600).
          lockoutEnabled = true;
          lockoutThreshold = 5;
          lockoutDurationSeconds = 900;
          lockoutCounterResetSeconds = 60;
        };
      };

      # A workload that authenticates as itself rather than holding a secret.
      # See 92-kubernetes.nix for the full field set.
      cluster-workload = {
        role = "no-access";
        auth.kubernetes = {
          tokenReviewMode = "api";
          kubernetesHost = "https://k8s.example.com:6443";
          allowedNamespaces = "apps,platform";
          allowedNames = "infisical-reader";
          allowedAudience = "infisical";
        };
      };
    };

    # -- identity templates --------------------------------------------------
    #
    # POST /api/v1/identity-templates
    #
    # A reusable auth configuration so that twenty identities pointing at the
    # same LDAP server or the same cluster do not restate its address, CA and
    # bind credentials twenty times. Three template kinds exist: ldap,
    # kubernetes, oidc.
    identityTemplates = {
      corp-ldap = {
        authMethod = "ldap";
        templateFields = {
          url = "ldaps://ldap.example.com";
          bindDN = "cn=infisical,ou=svc,dc=example,dc=com";
          bindPass.sopsFile = ./secrets/ldap.yaml;
          searchBase = "ou=people,dc=example,dc=com";
          ldapCaCertificate = null;
        };
      };

      main-cluster = {
        authMethod = "kubernetes";
        templateFields = {
          tokenReviewMode = "api"; # "api" | "gateway"
          kubernetesHost = "https://k8s.example.com:6443";
          verifyTlsCertificate = true;
          allowedAudience = "infisical";
        };
      };

      corp-oidc = {
        authMethod = "oidc";
        templateFields = {
          oidcDiscoveryUrl = "https://idp.example.com/.well-known/openid-configuration";
          boundIssuer = "https://idp.example.com";
          boundAudiences = "infisical";
        };
      };
    };

    # -- project templates ---------------------------------------------------
    #
    # POST /api/v1/project-templates
    #
    # This is the declarative project object Infisical already models, and it
    # is the reason `shouldCreateDefaultEnvs` behaves the way it does: the
    # flag is only consulted on the "default" template path, because any
    # other template brings its own environments[].
    #
    # A project then names it: projects.foo.template = "standard".
    projectTemplates.standard = {
      type = "secret-manager"; # |cert-manager|kms|secret-scanning|pam

      # name, slug and position are ALL required here, unlike the standalone
      # environment create where position is optional.
      environments = {
        dev = { name = "Development"; position = 1; };
        staging = { name = "Staging"; position = 2; };
        prod = { name = "Production"; position = 3; };
      };

      roles.deployer = {
        name = "Deployer";
        permissions = [
          {
            subject = "secrets";
            action = [ "read" "readValue" ];
            conditions = {
              environment."$in" = [ "dev" "staging" ];
              secretPath."$glob" = "/**";
            };
          }
        ];
      };

      # Bindings the template applies at instantiation. `users` is by
      # username, `groups` by slug, `identities` by id.
      groups.developers.roles = [ "deployer" ];
      identities.fleet-sync.roles = [ "admin" ];
      users."ops@example.com".roles = [ "admin" ];

      # Identities created *by* the project rather than bound into it.
      projectManagedIdentities.ci.roles = [ "deployer" ];
    };
  };
}
