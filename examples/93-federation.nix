# Federation and identity: sub-organizations, SSO, SCIM, LDAP, sharing.
#
# The theme is everything that crosses a boundary — between organizations,
# between Infisical instances, or between Infisical and whoever owns the
# question of who a person is.
#
# Read the negative results first, because three of the five things people
# assume are here are not:
#
#   - SCIM is ONE endpoint. Group-to-role mappings, PUT only. There is no
#     token management API, so the SCIM token is minted in the UI.
#   - Sub-organizations have almost no surface: name, slug, memberships.
#     They inherit the parent's SSO and cannot define their own roles.
#   - OAuth clients do not exist as an API at all. `oauth-clients` is a
#     permission subject with read/create/edit/delete actions and there is no
#     endpoint those actions govern in the public spec.
{
  infisical.instances.lab.organization = {

    # ========================================================================
    # SUB-ORGANIZATIONS
    # ========================================================================
    #
    # POST /api/v1/sub-organizations  { name (1-64), slug (1-64) }
    #
    # The entire create surface. Two fields.
    #
    # Unlike a top-level organization, a sub-org CAN choose its slug — which
    # is a small mercy given that top-level orgs cannot and end up named
    # things like `xg-capital-strategies-6-ec-e`. Omit it and one is
    # generated.
    #
    # A PATCH with only `name` updates BOTH name and slug. To change the name
    # and keep the slug you must send both explicitly. A reconciler that
    # patches the name because the display string drifted will silently
    # re-slug the organization, and the slug is what everything else
    # addresses by.
    subOrganizations = {
      client-a = {
        name = "Client A";
        slug = "client-a";
        # POST /api/v1/sub-organizations/{subOrgId}/memberships
        # The spec defines a null request body for this, so the shape is
        # path-parameter driven and not visible here. Unverifiable from the
        # document; needs a live call before it is built.
        memberships = [ ];
      };
    };

    # What a sub-org does NOT get:
    #
    #   - its own SSO. SAML and OIDC are configured on the parent and
    #     inherited read-only.
    #   - its own role definitions. Roles are parent-scoped.
    #   - a project-creation API of its own; projects are created at org
    #     scope and associated.
    #
    # So a sub-org is a membership and billing partition, not an isolation
    # boundary. For real separation — the XG / Skrybit / jeirslab case — the
    # answer remains separate organizations, which is what the multi-org
    # support in nixfisical already does.

    # ========================================================================
    # SSO
    # ========================================================================

    # POST /api/v1/sso/config
    #
    # Required: organizationId, authProvider, isActive, entryPoint, issuer,
    # cert. Note isActive is REQUIRED — there is no staging a config and
    # enabling it later without deciding now.
    #
    # authProvider is six values and they are per-vendor rather than generic:
    # okta-saml, azure-saml, jumpcloud-saml, google-saml, keycloak-saml,
    # auth0-saml. There is no plain `saml`. An IdP not on that list cannot be
    # configured as SAML even if it speaks SAML perfectly — which rules out
    # Authentik, the one actually running in this lab. OIDC below is the path
    # for it.
    saml = {
      authProvider = "keycloak-saml";
      isActive = true;
      entryPoint = "https://idp.example.com/realms/lab/protocol/saml";
      issuer = "https://idp.example.com/realms/lab";
      cert.sopsFile = ./secrets/saml.yaml;   # the IdP signing certificate
      enableGroupSync = true;
    };

    # POST /api/v1/sso/oidc/config
    #
    # Required: configurationType, clientId, clientSecret, isActive,
    # organizationId.
    #
    # configurationType = "discoveryURL" and everything below the discovery
    # URL is fetched. "custom" means supplying issuer, authorizationEndpoint,
    # jwksUri, tokenEndpoint and userinfoEndpoint by hand — for an IdP whose
    # discovery document is wrong or absent.
    #
    # This is the path for Authentik, which is what the lab actually runs.
    oidc = {
      configurationType = "discoveryURL";    # "custom" | "discoveryURL"
      discoveryURL = "https://idp.internal/application/o/infisical/.well-known/openid-configuration";
      clientId.value = "infisical";
      clientSecret.sopsFile = ./secrets/oidc.yaml;
      isActive = true;

      # Restricts which verified emails may sign in at all. The cheapest
      # guard against an IdP that is more permissive than you assumed.
      allowedEmailDomains = "example.com";

      # Infisical creates and removes its groups from OIDC claims. Powerful
      # and sharp: group membership then drives project access, and an IdP
      # group rename becomes an access change with no deploy. Default false.
      manageGroupMemberships = false;

      jwtSignatureAlgorithm = "RS256";  # RS256 | HS256 | RS512 | EdDSA

      # Custom-type fields, unused when discoveryURL is set:
      #   issuer, authorizationEndpoint, jwksUri, tokenEndpoint,
      #   userinfoEndpoint
    };

    # -- the break-glass problem ----------------------------------------------
    #
    # `bypass-sso-enforcement` is not a config object — it is an ACTION on
    # the `sso` subject in an organization role:
    #
    #   { subject = "sso"; action = "bypass-sso-enforcement"; }
    #
    # Which means the ability to log in when SSO is broken is granted by
    # role, and it has to exist BEFORE SSO is enforced. Enforcing SSO with no
    # role carrying this action and then having the IdP fail is a lockout
    # with no path back that does not involve the database.
    #
    # The `sso` subject's full action list: read, create, edit, delete,
    # bypass-sso-enforcement. No conditions — at organization scope only
    # `app-connections` takes those.

    # ========================================================================
    # LDAP as a login source
    # ========================================================================
    #
    # POST /api/v1/ldap/config
    #
    # Distinct from BOTH the ldap app-connection (50-connections.nix, for
    # rotations) and ldap identity auth (a machine authenticating). This one
    # is humans logging in.
    #
    # Required: organizationId, isActive, url, bindDN, bindPass, searchBase,
    # groupSearchBase.
    ldap = {
      isActive = true;
      url = "ldaps://dc.internal";
      bindDN = "cn=infisical,ou=svc,dc=example,dc=com";
      bindPass.sopsFile = ./secrets/ldap.yaml;
      searchBase = "ou=people,dc=example,dc=com";
      groupSearchBase = "ou=groups,dc=example,dc=com";
      groupSearchFilter = "(objectClass=groupOfNames)";

      # Default `uidNumber`. Worth thinking about: this is the join key
      # between an LDAP entry and an Infisical user, so changing it later
      # re-identifies everyone.
      uniqueUserAttribute = "uidNumber";

      # Default "(uid={{username}})".
      searchFilter = "(uid={{username}})";

      caCert = null;
      # mTLS to the directory.
      clientCertificate = null;
      clientKeyCertificate = null;
    };

    # ========================================================================
    # SCIM
    # ========================================================================
    #
    # PUT /api/v1/scim/group-org-role-mappings
    #   { mappings: [ { groupName, roleSlug } ] }
    #
    # That is the whole writable SCIM surface. One endpoint, PUT semantics —
    # the list sent REPLACES the list stored, so a partial update deletes
    # every mapping it omits. Exactly the shape a declaration wants, and
    # exactly the shape that punishes a reconciler that patches.
    #
    # There is no SCIM token endpoint. The bearer token the IdP presents is
    # minted in the UI and cannot be declared, so bootstrapping SCIM is a
    # manual step regardless of what is written here.
    scimGroupRoleMappings = {
      "lab-admins" = "admin";
      "lab-developers" = "member";
      "lab-auditors" = "auditor";     # the custom role from 20-organization
    };
  };

  # ==========================================================================
  # INSTANCE-TO-INSTANCE
  # ==========================================================================
  #
  # Two objects, both already shown elsewhere, listed together because they
  # are the only real federation in the product:
  #
  #   app-connection  kind = "external-infisical"   (50-connections.nix)
  #     One Infisical authenticating to another as a machine identity.
  #     Method: machine-identity-universal-auth, and only that.
  #     Forbids gateways and rotation outright.
  #
  #   secret-sync     destination = "external-infisical"  (60-syncs.nix)
  #     Push a path from here to a (projectId, environment, secretPath)
  #     there. initialSyncBehavior takes all three values, so unlike most
  #     destinations there IS a non-destructive first run:
  #     import-prioritize-destination.
  #
  # That is a one-way push, not a trust relationship. The upstream does not
  # know it is being federated INTO, which means the direction of control is
  # whichever side holds the connection. For a hub-and-spoke estate — lab
  # pushing shared credentials down to XG and Skrybit — the hub holds the
  # connections and the spokes need nothing.
  #
  # ==========================================================================
  # LEGACY INTEGRATIONS
  # ==========================================================================
  #
  # POST /api/v1/integration — marked deprecated: true in the spec itself.
  # The predecessor to secret-syncs, carrying integrationAuthId and a
  # provider-specific `metadata` blob.
  #
  # Not modelled and will not be. It is listed only so that finding one on a
  # live server is recognised as something to migrate to a sync rather than
  # something to declare.
}
