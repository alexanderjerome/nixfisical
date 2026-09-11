# The instance: where the server is, how we reach it, how it reaches back.
#
# Everything else in this directory hangs off an instance. An instance is one
# Infisical server and one organization within it. Two organizations on the
# same server are two instances here, because an access token is scoped to
# exactly one and there is no call that crosses the boundary.
#
# This file also holds the two pieces of network plumbing — gateways and
# relays — because they are properties of the deployment rather than of any
# project, even though a gateway is referenced from project-scoped objects.
{
  infisical = {

    # -- resolvers -----------------------------------------------------------
    #
    # Not an API concept. This is the one place the module invents something,
    # and it exists so that the module does not have to care where values
    # come from.
    #
    # A resolver is a program. It reads the descriptor as JSON on stdin,
    # writes the raw value bytes to stdout, and a non-zero exit fails that
    # entry. That contract is small enough that sops, vault, pass, 1Password,
    # gpg, age and `echo` all satisfy it without adaptation.
    #
    # The consequence worth stating: the manifest that leaves Nix eval
    # contains descriptors, never plaintext. Not because we are careful —
    # because there is no code path that could put a value there.
    resolvers = {
      # Registered by the module itself when sops-nix is present. Listed here
      # so that `sopsFile` is not magic.
      sops.command = "nixfisical-resolve-sops";

      vault.command = "nixfisical-resolve-vault";
      pass.command = "/run/current-system/sw/bin/pass-resolver";

      # The trivial one, useful for testing the wiring without a keyring.
      # Reads the descriptor's `literal` field back out. Obviously not for
      # anything real.
      echo.command = "nixfisical-resolve-echo";
    };

    instances.lab = {
      # -- reaching the server ----------------------------------------------
      url = "https://infisical.example.com";

      # Matched by id, then slug, then name. Slug is the stable one; name is
      # what a human typed. Organizations, unlike projects, cannot choose
      # their slug at creation — the server generates one with a random
      # suffix, which is how you end up matching on something like
      # `xg-capital-strategies-6-ec-e`.
      #
      # Selection only. The organization's contents are declared under the
      # same attribute; see 20-organization.nix.
      organization.slug = "lab";

      # A machine identity's client id and secret. Universal auth, because
      # that is the method that works from anywhere without the reconciler
      # having a cloud identity of its own.
      #
      # The identity needs enough organization-level rights to do whatever
      # the declaration asks for. An admin token is the easy answer and a bad
      # habit; see 20-organization.nix for narrowing it.
      auth.sopsFile = ./secrets/infisical-admin.yaml;

      # Trust the server's certificate. False is for a self-signed
      # instance you have not got round to fixing, and should be loud.
      verifyTls = true;

      # -- gateways ----------------------------------------------------------
      #
      # POST /api/v3/gateways
      #
      # A gateway is how Infisical reaches something it cannot route to: a
      # database on a private VLAN, a Kubernetes API server behind NAT, an
      # LDAP directory that was never meant to face the internet. The gateway
      # dials out and holds the connection open, so nothing is exposed
      # inbound.
      #
      # Anything with a `gatewayId` field can be routed through one: app
      # connections, dynamic secrets, identity auth, HSM connectors, PKI
      # discovery. For a homelab that is most of the interesting half of the
      # product, because most of it is on the far side of a firewall.
      gateways = {
        # The simplest method, and the one with a bearer token to look after.
        # The body is literally { method = "token"; } — there is nothing to
        # configure. Enrolment is then:
        #
        #   POST /api/v3/gateways/{gatewayId}/token-auth/generate-enrollment-token
        #     -> { token, expiresAt }
        #
        # The token is short-lived and single-use in spirit. It is a
        # bootstrap credential, not a stored one, which is why it is not
        # declared here: the reconciler mints it and hands it over, or a
        # human does.
        lab-lan.authMethod.method = "token";

        # Enrolling from inside a cluster with a ServiceAccount token, so no
        # long-lived credential exists at all. Full field set in
        # 92-kubernetes.nix.
        cluster.authMethod = {
          method = "kubernetes";
          allowedNamespaces = "infisical-gateway"; # REQUIRED, max 1024
          allowedNames = "infisical-gateway";      # REQUIRED, max 1024
          allowedAudience = "infisical-gateway";   # max 255, default ""
          kubernetesHost = "https://k8s.internal:6443";
          tokenReviewMode = "api";                 # "api" | "gateway"
          verifyTlsCertificate = true;
          caCertificate = null;                    # max 10240
          tokenReviewerJwt.sopsFile = ./secrets/k8s-reviewer.yaml; # max 8192
        };

        # Enrolling by EC2 instance identity.
        aws-vpc.authMethod = {
          method = "aws";
          stsEndpoint = "https://sts.amazonaws.com/"; # default, 1-255
          allowedPrincipalArns = "arn:aws:iam::123456789012:role/gateway";
          allowedAccountIds = "123456789012";
        };
      };

      # -- gateway pools -------------------------------------------------------
      #
      # There is no way to declare one. `gatewayPoolId` appears as a foreign
      # key on gateway auth, identity auth, dynamic secrets, identity
      # templates, HSM connectors and PKI discovery jobs, and there is no
      # POST anywhere in 1479 paths that creates a pool. Either it is EE-only
      # or unreleased.
      #
      # Treat a pool id as an opaque value obtained from somewhere else. Do
      # not plan on managing one.

      # -- relays --------------------------------------------------------------
      #
      # GET /api/v1/relays, and that is the entire surface. List only. No
      # create, no update, no delete.
      #
      # So relays are not declarable, and this block does not exist. It is
      # recorded here because "why is there no relays option" is otherwise a
      # question someone asks twice.
      #
      # The practical difference from a gateway: a gateway is a thing you
      # enrol and configure, a relay is a thing that is simply there.

      # -- instance-wide behaviour --------------------------------------------
      #
      # Not API fields — reconciler policy. They live on the instance because
      # they govern the whole run.
      settings = {
        # Compute and print the plan, change nothing. The only safe first
        # run against a server someone else built.
        dryRun = false;

        # A feature the server does not have — groups on an unlicensed
        # self-hosted instance, EE approval routes, audit log retention on
        # cloud — either warns and skips, or aborts the run.
        #
        # "warn" is right. Licence gating is not a declaration error, and a
        # run that aborts halfway has left the server in a state nobody
        # declared. Set "abort" when the declaration is the contract and a
        # silent gap is worse than a failed deploy.
        onUnsupported = "warn"; # "warn" | "abort"

        # Mutating secret calls can come back with { approval } instead of
        # { secret } when an EE approval policy covers the path. The request
        # was accepted; it just has not happened yet.
        #
        # We cannot declare those policies — they are not in the public spec
        # at all — so the only choice is what to do when one bites.
        # "pending" records it, reports it, and does not call it a failure,
        # because on the next run it will still be pending and nothing is
        # wrong.
        onApprovalRequired = "pending"; # "pending" | "fail"
      };
    };
  };
}
