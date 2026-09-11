# Certificate management: a CA, what it will sign, and where certs go.
#
# This is the largest single feature in the API and the one furthest from
# what nixfisical does today. It is here because a homelab with an internal
# CA has the same problem this solves — a root key that lives somewhere, a
# policy nobody wrote down, and certificates that expire on a Sunday.
#
# Structurally it is split across two prefixes, and the split is historical
# rather than principled:
#
#   /api/v1/pki/**           CAs by the older model, templates, subscribers,
#                            collections
#   /api/v1/cert-manager/**  CAs by the newer model, policies, profiles,
#                            signers, syncs, alerts, applications, ACME,
#                            HSM connectors, discovery
#
# Where both offer something — certificate templates in pki vs certificate
# policies + profiles in cert-manager — the cert-manager pair is the more
# expressive and the one to build against.
{
  infisical.instances.lab.projects.pki = {
    projectName = "pki";

    # Same project object as everywhere else, different type. The type is
    # what makes the cert-manager endpoints legal against it.
    type = "cert-manager";

    # -- certificate authorities ---------------------------------------------
    #
    # POST /api/v1/cert-manager/ca/{type}
    #
    # Nine types: internal, acme, azure-ad-cs, adcs, aws-acm-public-ca,
    # aws-pca, digicert, godaddy, venafi-tpp.
    #
    # Shared envelope on every one: name (REQUIRED, 1-64), status (REQUIRED),
    # configuration (REQUIRED, type-specific).
    #
    # `status` being REQUIRED at creation is unusual and worth noting: you
    # declare a CA into `active`, `disabled` or `pending-certificate`. The
    # third is the intermediate-awaiting-signature state, which means the
    # lifecycle is visible in the object rather than implied.
    certificateAuthorities = {

      # A root we generate and hold. The keySource decision below is the one
      # that actually matters here.
      lab-root = {
        type = "internal";
        status = "active";
        configuration = {
          type = "root";            # "root" | "intermediate"

          # 21 values. Classical: RSA_2048/3072/4096,
          # EC_prime256v1/secp384r1/secp521r1. Post-quantum: ML-DSA-44/65/87
          # and twelve SLH-DSA variants (SHA2 and SHAKE, 128/192/256, f and
          # s). The f/s suffix is fast-vs-small signatures — SLH-DSA
          # signatures are large enough that the choice is a protocol
          # decision, not a preference.
          keyAlgorithm = "EC_secp384r1";

          # "local" keeps the private key in Infisical, encrypted under the
          # project KMS key. "hsm" keeps it in hardware and Infisical never
          # holds it.
          #
          # For a root with a ten-year life this is the whole question. Local
          # means the root key's security is the server's security.
          keySource = "local";      # "local" | "hsm"
          hsmConnectorId = null;
          hsmKeyLabel = null;

          # Subject DN, all optional, all max 255, all defaulting to "".
          # A CA whose DN is empty strings is valid and unusable.
          commonName = "Lab Root CA";
          organization = "lab";
          ou = "infrastructure";
          country = "US";
          province = "";
          locality = "";
          friendlyName = "Lab Root CA";

          # RFC3339. Omit for server defaults.
          notBefore = null;
          notAfter = null;

          # -1 for unlimited. On a root that signs one intermediate and
          # nothing else, 1 is the honest value and constrains a compromise.
          maxPathLength = 1;

          crlDistributionPointUrls = [ ];
          disableManagedCrlDistributionPointUrl = false;

          parentCaId = null;        # set on an intermediate
        };
      };

      # Let's Encrypt via DNS-01. The DNS challenge is the only one modelled
      # — there is no HTTP-01 variant — which means an ACME CA here always
      # needs an app connection to a DNS provider that can write TXT records.
      # That is four providers: route53, cloudflare, dns-made-easy,
      # azure-dns.
      public = {
        type = "acme";
        status = "active";
        configuration = {
          directoryUrl = "https://acme-v02.api.letsencrypt.org/directory";
          accountEmail = "ops@example.com";
          dnsAppConnectionId = "lab-cloudflare";
          dnsProviderConfig = {
            provider = "cloudflare";
            hostedZoneId = "…zone id…";
          };
          # External Account Binding, for an ACME CA that requires it.
          eabKid = null;                            # max 64
          eabHmacKey = null;                        # max 512
          # Override the resolver used to check propagation. Useful when
          # split-horizon DNS makes the local resolver lie.
          dnsResolver = "1.1.1.1";
        };
      };
    };

    # -- what may be signed ---------------------------------------------------
    #
    # POST /api/v1/cert-manager/certificate-policies
    #
    # A policy is a constraint set, not a template: every field takes
    # allowed / required / denied lists rather than a value. It says what a
    # request may contain, and it is enforced at signing time.
    #
    # This is the object that makes an internal CA safe to expose. Without
    # it, anything that can request a certificate can request one for any
    # name.
    certificatePolicies.internal-server = {
      description = "TLS server certs for *.internal";

      subject = [
        { type = "common_name"; allowed = [ "*.internal" ]; required = [ ]; }
        { type = "organization"; required = [ "lab" ]; }
        # domain_component is special: max 25 items, comma-separated
        # most-specific-first, and `denied` rejects the component anywhere in
        # the chain rather than only at that position.
      ];

      sans = [
        { type = "dns_name"; allowed = [ "*.internal" ]; }
        { type = "ip_address"; denied = [ "*" ]; }
      ];

      keyUsages = {
        required = [ "digital_signature" "key_encipherment" ];
        denied = [ "key_cert_sign" "crl_sign" ];
      };

      extendedKeyUsages = {
        allowed = [ "server_auth" ];
        denied = [ "any_purpose" "code_signing" ];
      };

      # Duration string. The ceiling, enforced regardless of what is asked
      # for. 90 days is the number that forces automation to exist.
      validity.max = "2160h";

      basicConstraints = {
        isCA = "denied";          # "allowed" | "required" | "denied"
        maxPathLength = -1;
      };

      algorithms = {
        signature = [ "ECDSA-SHA384" "RSA-SHA256" ];
        keyAlgorithm = [ "EC_secp384r1" "RSA_2048" ];
      };
    };

    # -- how it is issued ------------------------------------------------------
    #
    # POST /api/v1/cert-manager/certificate-profiles
    #
    # A profile binds a policy to a CA and supplies defaults for what the
    # request leaves out. Policy = what is allowed; profile = what happens.
    # They are separate so one policy can be enforced by several CAs.
    certificateProfiles.internal-server = {
      slug = "internal-server";
      certificatePolicyId = "internal-server";  # by name; resolved
      caId = "lab-root";
      issuerType = "ca";                        # "ca" | "self-signed"
      defaults = {
        ttlDays = 90;
        commonName = "";
        keyAlgorithm = "EC_secp384r1";
        signatureAlgorithm = "ECDSA-SHA384";
      };
    };

    # -- who gets certificates -------------------------------------------------
    #
    # POST /api/v1/pki/subscribers
    #
    # A named thing that holds a certificate and renews it. This is the
    # declarative unit — one per service that needs TLS — and the closest
    # analogue to a cert-manager Certificate resource.
    subscribers.cli-proxy = {
      caId = "lab-root";
      commonName = "cli-proxy.internal";
      subjectAlternativeNames = [ "cli-proxy.internal" "proxy.internal" ];
      ttl = "2160h";
      status = "active";                  # "active" | "disabled"
      keyUsages = [ "digitalSignature" "keyEncipherment" ];
      extendedKeyUsages = [ "serverAuth" ];

      # Without this a certificate expires and somebody finds out from a
      # browser. The renewal period wants to be comfortably more than the
      # longest plausible outage.
      enableAutoRenewal = true;
      autoRenewalPeriodInDays = 30;
    };

    # -- where certificates go -------------------------------------------------
    #
    # POST /api/v1/cert-manager/pki-syncs/{destination}
    #
    # The same idea as 60-syncs.nix, for certificates. Twelve destinations:
    # aws-certificate-manager, aws-elastic-load-balancer, aws-secrets-manager,
    # azure-key-vault, chef, cloudflare-custom-certificate,
    # gcp-certificate-manager, kemp-loadmaster, linux-server, netscaler,
    # nutanix-prism-central, windows-server.
    #
    # `linux-server` and `windows-server` are the ones that matter here: they
    # write the certificate to a path on a host over SSH or WinRM, set its
    # mode and owner, and run a command afterwards. That is the last mile
    # fleetkit currently does with sops-nix, done from the other side.
    pkiSyncs.proxy-cert = {
      destination = "linux-server";
      connectionId = "lab-ssh";
      subscriberId = "cli-proxy";
      isAutoSyncEnabled = true;             # default FALSE here, unlike
                                            # secret syncs where it is true
      destinationConfig = {
        destinationPath = "/var/lib/cli-proxy/tls"; # 1-4096
        host = "cli-proxy.internal";                # 1-253
        port = 22;
        # ssh-keyscan output. Pinning it is what stops the first sync from
        # trusting whatever answers.
        sshHostKeys = null;                         # max 8192
      };
      syncOptions = {
        # REQUIRED. How the files are named at the destination.
        certificateNameSchema = "{{subscriberName}}";
        exportFormat = "pem";               # "pem" | "pkcs12"
        pemCertificateExtension = "pem";    # "pem" | "crt"
        includePrivateKey = true;
        includeRootCa = false;
        combineCertificateChain = false;
        fileMode = "0644";                  # octal string
        privateKeyFileMode = "0600";
        owner = "cli-proxy";                # max 32
        group = "cli-proxy";                # max 32
        canRemoveCertificates = false;
        # Both max 8192. postSyncCommand is the reload; healthCheckCommand
        # is what decides the reload worked. A sync with a postSyncCommand
        # and no healthCheckCommand is a service that restarts into a broken
        # config and reports success.
        postSyncCommand = "systemctl reload cli-proxy";
        healthCheckCommand = "systemctl is-active cli-proxy";
      };
    };

    # -- expiry alerts ---------------------------------------------------------
    #
    # POST /api/v1/cert-manager/alerts
    alerts.expiry = {
      eventType = "expiration";     # |renewal|issuance|revocation
      alertBefore = "30d";
      enabled = true;
      filters = [ ];                # certificate selection criteria
      channels = [ ];               # notification channels
    };

    # -- signers and approval --------------------------------------------------
    #
    # POST /api/v1/cert-manager/signers
    # PUT  /api/v1/cert-manager/signers/{signerId}/approval-policy
    #
    # This is the ONE approval policy in the entire public API. Secret
    # approvals and access approvals are EE routes that do not appear in the
    # spec at all — see the README. So the only multi-party authorisation we
    # can declare is on certificate signing.
    #
    # Multi-step, with per-step quorum:
    #
    #   steps = [ { stepNumber = 1; name = "security";
    #               requiredApprovals = 2;
    #               approverUserIds = [ ]; approverGroupIds = [ ]; } ];
    #   constraints = { maxSignings = 10; maxWindowDuration = "24h"; };
    #
    # Which is the right shape for a root CA: signing an intermediate should
    # take two people and should be rate-limited, and both of those are
    # expressible here.

    # -- also present, not modelled --------------------------------------------
    #
    #   PKI collections     POST /api/v1/pki/collections — grouping only
    #   PKI applications    POST /api/v1/cert-manager/applications — a name
    #                       plus profileIds, used to scope the ACME directory
    #   PKI discovery       POST /api/v1/cert-manager/discovery-jobs — scan a
    #                       network for certificates we did not issue. Takes
    #                       a gatewayId, so it can scan a private VLAN. The
    #                       most immediately useful thing in this file for an
    #                       estate that has been running for years.
    #   PKI installations   GET only. Not declarable.
    #   HSM connectors      POST /api/v1/cert-manager/hsm-connectors
    #                       { name (1-32), credentials { slotLabel (1-128),
    #                         pin (1-512), keyNamePrefix }, gatewayId }
    #                       PKCS#11. The `pin` is a resolver descriptor.
    #   ACME protocol       ~15 RFC 8555 endpoints (new-nonce, new-order,
    #                       finalize, challenges...). Protocol surface, not
    #                       configuration — an ACME client talks to these.
    #                       The declarable part is the profile that exposes
    #                       the directory, plus EAB rotate/reveal.
  };
}
