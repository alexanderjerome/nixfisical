# Every Kubernetes touchpoint in the API, in one place.
#
# Kubernetes appears in Infisical four times, and they are four unrelated
# features that happen to share a word. Collected here because the question
# "how does this work on Kubernetes" is one question to a reader and four
# answers in the spec:
#
#   1. kubernetes identity auth  — a pod authenticates to Infisical as itself
#   2. kubernetes identity template — that auth config, shared across many
#   3. kubernetes dynamic secrets — Infisical mints short-lived k8s credentials
#   4. gateway kubernetes auth   — a gateway enrols using a ServiceAccount token
#
# Three things that do NOT exist, stated up front because each is the sort of
# absence you otherwise discover by writing code against it:
#
#   - There is no Kubernetes app-connection kind. Not a kubeconfig one either.
#     The 85 connection kinds do not include the cluster. So nothing in
#     50-connections.nix / 60-syncs.nix / 70-rotations.nix reaches a cluster.
#   - There is no Kubernetes secret-sync destination. Infisical will not write
#     a Secret object into a namespace through this API. That direction is the
#     Kubernetes Operator's job, a separate product that reads from Infisical;
#     it is not declarable here.
#   - There are no gateway-pool CRUD endpoints at all. `gatewayPoolId` appears
#     as a foreign key on identity auth, dynamic secrets, templates and
#     connections, and there is no POST that creates one. Either it is EE-only
#     or it is unreleased. Treat a pool id as an opaque value obtained
#     elsewhere; do not plan to declare one.
{
  infisical.instances.lab = {

    # -- 1. an identity that authenticates with a ServiceAccount token -------
    #
    # POST /api/v1/auth/kubernetes-auth/identities/{identityId}
    #
    # The workload presents its projected ServiceAccount token; Infisical
    # calls TokenReview to validate it and checks the resulting namespace and
    # name against the allow-lists below. No shared secret exists anywhere,
    # which is the entire point of the method.
    organization.identities.cluster-workload = {
      role = "no-access";

      auth.kubernetes = {
        # Who Infisical will accept. BOTH are REQUIRED, both are
        # comma-separated strings rather than lists — the wire type is a
        # single string, so this stays a string. `*` wildcards are honoured.
        #
        # There is no implicit default. Omitting either is a 400, which is
        # the correct design: an empty allow-list that meant "everything"
        # would be a catastrophe waiting on a typo.
        allowedNamespaces = "apps,platform";
        allowedNames = "infisical-reader,cli-proxy";

        # The `aud` claim the token must carry, max 1000 chars. Empty means
        # the cluster's default audience is accepted, which in practice is
        # the API server's own. Setting it narrows a stolen token's blast
        # radius to this one relying party — worth doing.
        allowedAudience = "infisical";

        # How the TokenReview happens.
        #
        #   "api"     (default) Infisical calls the cluster's API server
        #             directly. Needs kubernetesHost reachable from the
        #             Infisical server and a tokenReviewerJwt with
        #             system:auth-delegator.
        #   "gateway" a gateway inside the cluster performs the TokenReview
        #             on Infisical's behalf. Infisical never needs to reach
        #             the API server at all.
        #
        # "gateway" is what makes this work for a private cluster. It is also
        # what makes it work when Infisical is the thing outside and the
        # cluster is the thing behind NAT — which is the normal shape for a
        # homelab.
        tokenReviewMode = "api";

        # 1-255 chars, nullable. Required in practice for tokenReviewMode =
        # "api"; leave null when the gateway does the review.
        kubernetesHost = "https://k8s.example.com:6443";

        # The cluster CA, PEM. Note the interaction: supplying a non-empty
        # caCert auto-promotes verifyTlsCertificate to true server-side, even
        # if you sent false. You cannot pin a CA and then not check it.
        caCert = null;
        verifyTlsCertificate = true;

        # The JWT Infisical presents when calling TokenReview. A secret, so
        # it goes through the ordinary value machinery — not a literal.
        #
        # Only needed for tokenReviewMode = "api". Responses never return it;
        # they return a read-only `hasTokenReviewerJwt` boolean instead,
        # which means the reconciler cannot diff this field and must either
        # always write it or track it out of band.
        tokenReviewerJwt.sopsFile = ./secrets/k8s-reviewer.yaml;

        # Mutually exclusive with each other. Route the TokenReview through a
        # gateway rather than out of the Infisical server directly.
        gatewayId = null;
        gatewayPoolId = null;

        # Same envelope as every other auth method. Seconds; 0-315360000;
        # both default to 2592000 (30 days). Trusted IPs default to open.
        accessTokenTTL = 3600;
        accessTokenMaxTTL = 86400;
        accessTokenNumUsesLimit = 0;
        accessTokenTrustedIps = [ "10.42.0.0/16" ];

        # Points at the template below. Everything the template supplies can
        # still be overridden field by field here.
        #
        # PATCH with templateId = null unlinks the identity from the template
        # while KEEPING the settings it had copied. Unlinking is not
        # reverting — the identity keeps working, it just stops tracking.
        templateId = null;
      };
    };

    # -- 2. the same configuration, shared ----------------------------------
    #
    # POST /api/v1/identity-templates  { authMethod = "kubernetes"; ... }
    #
    # Twenty identities in one cluster should not restate the host, the CA
    # and the reviewer JWT twenty times. The template carries the
    # cluster-shaped fields; the identity carries the workload-shaped ones.
    #
    # Note what is NOT in templateFields: allowedNamespaces and allowedNames.
    # That is deliberate on the API's part and it is the right split — the
    # cluster is shared, the allow-list is per identity. A template that
    # carried the allow-list would be a template for one workload.
    organization.identityTemplates.main-cluster = {
      authMethod = "kubernetes";
      templateFields = {
        tokenReviewMode = "gateway"; # "api" | "gateway"
        kubernetesHost = "https://k8s.internal:6443";
        caCert = null;               # max 102400
        verifyTlsCertificate = true;
        tokenReviewerJwt.sopsFile = ./secrets/k8s-reviewer.yaml; # max 65536
        allowedAudience = "infisical"; # max 1000, default ""
        gatewayId = null;
        gatewayPoolId = null;
      };
    };

    # -- 3. Infisical mints cluster credentials on demand --------------------
    #
    # POST /api/v1/dynamic-secrets  { provider.type = "kubernetes"; ... }
    #
    # This is the opposite direction from (1). There, a pod proves who it is
    # to Infisical. Here, something asks Infisical for a token that works
    # against the cluster, and gets a lease with a TTL.
    #
    # Addressed by projectSlug and environmentSlug rather than projectId —
    # the dynamic-secrets routes are the one place in the API that does this.
    # See 80-dynamic-secrets.nix.
    projects.apps.dynamicSecrets.cluster-admin-token = {
      environmentSlug = "prod";
      path = "/k8s";
      defaultTTL = "1h";
      maxTTL = "8h";

      provider = {
        type = "kubernetes";

        # Shared by both credential types.
        url = "https://k8s.example.com:6443";
        clusterToken.sopsFile = ./secrets/k8s-admin.yaml;
        ca = null;
        sslEnabled = false;         # default false
        sslRejectUnauthorized = true;
        authMethod = "api";         # "gateway" | "api", default "api"
        gatewayId = null;
        gatewayPoolId = null;

        # A oneOf, discriminated on credentialType. The two branches take
        # genuinely different required fields, so this is not a flag — it is
        # two providers sharing a name.
        #
        #   "static"  — mint a token for a ServiceAccount that already
        #               exists. You manage the SA and its RBAC; Infisical
        #               only calls TokenRequest against it.
        #               requires: serviceAccountName, namespace, audiences
        #
        #   "dynamic" — Infisical creates a ServiceAccount, binds it to a
        #               Role or ClusterRole you name, issues a token, and
        #               tears the whole lot down when the lease expires.
        #               requires: namespace, roleType, role, audiences
        #
        # "dynamic" needs Infisical to hold rights to create SAs and
        # RoleBindings in that namespace, which is a meaningfully larger
        # grant than "static". Choose "static" unless the ephemerality is the
        # thing you actually want.
        credentialType = "static";
        serviceAccountName = "infisical-reader";
        namespace = "apps";
        audiences = [ "https://kubernetes.default.svc" ];

        # The "dynamic" branch, for reference:
        #
        #   credentialType = "dynamic";
        #   namespace = "apps";
        #   roleType = "role";          # "cluster-role" | "role"
        #   role = "secret-reader";
        #   audiences = [ "https://kubernetes.default.svc" ];
      };
    };

    # Leases: POST /api/v1/dynamic-secrets/leases
    #
    # The Kubernetes lease body accepts an optional `config.namespace` that
    # overrides the provider's namespace for that one lease. Every other
    # provider's lease config is empty. So one dynamic secret can serve many
    # namespaces, if the credentials it holds reach them.
    #
    # Leases are not declarable — a lease is a running thing with an expiry,
    # not desired state. This is here so the capability is recorded, and
    # because a reconciler that prunes dynamic secrets is destroying live
    # leases as a side effect and should say so.

    # -- 4. a gateway that enrols with a ServiceAccount token ----------------
    #
    # POST /api/v3/gateways  { authMethod = { method = "kubernetes"; ... } }
    #
    # A gateway is the thing that lets Infisical reach a private network:
    # rotations against a database with no public address, dynamic secrets in
    # a VPC, TokenReview against an unroutable API server. It dials out, so
    # nothing needs to be exposed inbound.
    #
    # Enrolling one in-cluster with a ServiceAccount token means the gateway
    # holds no long-lived credential either.
    gateways.cluster = {
      name = "cluster";

      authMethod = {
        method = "kubernetes";

        # Same REQUIRED pair as identity auth, same comma-separated string,
        # same `*` wildcards. Max 1024 each here.
        allowedNamespaces = "infisical-gateway";
        allowedNames = "infisical-gateway";

        # Max 255, default "".
        allowedAudience = "infisical-gateway";

        # Omit only when tokenReviewMode = "gateway" — that is the
        # self-reviewing case where no outbound call to the API server
        # happens at all.
        kubernetesHost = "https://k8s.example.com:6443";
        tokenReviewMode = "api";

        caCertificate = null;  # max 10240
        verifyTlsCertificate = true;
        tokenReviewerJwt.sopsFile = ./secrets/k8s-reviewer.yaml; # max 8192

        gatewayId = null;
        gatewayPoolId = null;
      };
    };

    # The other two gateway auth methods, for contrast:
    #
    #   { method = "token"; }   — the whole body. Then
    #                             POST /api/v3/gateways/{id}/token-auth/generate-enrollment-token
    #                             returns { token, expiresAt } which the
    #                             gateway presents once. Simplest, and the
    #                             one with a bearer token to look after.
    #   { method = "aws"; ... } — instance identity document.
    #
    # See 10-instance.nix.
  };
}
