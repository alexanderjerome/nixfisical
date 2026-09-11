# KMS keys, and the secret-scanning surface that shares this file.
#
# Two unrelated features, both of which are a project `type` rather than a
# thing inside a secret-manager project. A KMS project and a secret-manager
# project are the same object with a different `type`, and the endpoints that
# act on them are disjoint.
#
# Neither is built. Both are scaffolded because the project-type mechanism is
# the same one 90-pki.nix uses, and a module that models `type` as a real
# option gets all four for the price of one.
{
  infisical.instances.lab.projects = {

    # ========================================================================
    # KMS  —  /api/v1/kms/**
    # ========================================================================
    #
    # Encryption, decryption, signing and MAC as a service, with the private
    # key never leaving the server. The reason it appears in a secrets tool at
    # all is `kmsKeyId` on a secret-manager project (30-project.nix): a
    # project can be encrypted under a key declared here rather than under the
    # instance default.
    crypto = {
      projectName = "crypto";
      type = "kms";

      # POST /api/v1/kms/keys  { projectId, name, ... }
      keys = {
        secrets-cmk = {
          description = "CMK for the apps project";

          # encrypt-decrypt (default) | sign-verify | generate-verify-mac
          #
          # Not a hint — it constrains which operations the key will accept,
          # and it cannot be changed later. A sign-verify key will refuse to
          # encrypt.
          keyUsage = "encrypt-decrypt";

          # 14 values, and they are not interchangeable across keyUsage:
          #
          #   symmetric   aes-256-gcm, aes-128-gcm
          #   RSA         RSA_4096
          #   ECC         ECC_NIST_P256, ECC_NIST_P384, ECC_NIST_P521
          #   post-quantum ML_DSA_44, ML_DSA_65, ML_DSA_87
          #   MAC         HMAC_SHA_1, HMAC_SHA_224, HMAC_SHA_256,
          #               HMAC_SHA_384, HMAC_SHA_512
          #
          # The ML_DSA entries are FIPS 204 lattice signatures. Their presence
          # here — and the SLH-DSA set in 90-pki.nix — means post-quantum
          # signing is available today, which is worth knowing before
          # standing up a CA with a 20-year root.
          algorithm = "aes-256-gcm";

          # Default TRUE, and immutable after creation. An exportable key is
          # one whose private material can be pulled out via
          # POST /api/v1/kms/keys/bulk-export-private-keys.
          #
          # Defaulting to true is the wrong way round for anything the word
          # "KMS" implies, and it cannot be fixed later. Set it to false and
          # mean it.
          isExportable = false;

          hasDeleteProtection = true;
        };

        signing-key = {
          keyUsage = "sign-verify";
          algorithm = "ECC_NIST_P384";
          isExportable = false;
        };
      };

      # Operations, not declarations:
      #
      #   POST /api/v1/kms/keys/{keyId}/sign     { signingAlgorithm, data, isDigest }
      #   POST /api/v1/kms/keys/{keyId}/verify
      #   POST /api/v1/kms/keys/bulk-import      1-100 keys with keyMaterial
      #   POST /api/v1/kms/keys/bulk-export-private-keys   1-100 keyIds
      #
      # bulk-import takes `keyMaterial` — bringing an existing key in rather
      # than generating one. That is the migration path, and it is also the
      # one call in this file that carries private key bytes in a request
      # body. If it is ever declared, the material is a resolver descriptor
      # like anything else, never a literal.
      #
      # signingAlgorithm is its own 11-value enum, separate from the key's
      # `algorithm`: RSASSA_PSS_SHA_{256,384,512},
      # RSASSA_PKCS1_V1_5_SHA_{256,384,512}, ECDSA_SHA_{256,384,512},
      # ML_DSA_{44,65,87}. The key constrains which are legal.
    };

    # ========================================================================
    # SECRET SCANNING  —  /api/v2/secret-scanning/**
    # ========================================================================
    #
    # Watch repositories for committed credentials. A different project type
    # again, and the one feature here that consumes an app connection
    # (50-connections.nix) — it needs to reach GitHub, GitLab or Bitbucket.
    scanning = {
      projectName = "scanning";
      type = "secret-scanning";

      # PATCH /api/v2/secret-scanning/configs
      #
      # PATCH only — there is no POST. The config exists from project
      # creation and is edited, never created. A reconciler that assumes
      # create-then-patch everywhere gets a 404 here.
      #
      # `content` is a nullable string: the scanner's ruleset file verbatim,
      # not a structured object. So this is a file we hold and ship, and it
      # is the one place in the whole surface where the API takes an opaque
      # blob of somebody else's config format.
      #
      # Left as a path rather than `builtins.readFile ./scanning-rules.toml`
      # on purpose: readFile evaluates, so a missing file breaks eval of the
      # whole declaration, whereas every other path in this directory is an
      # inert literal. The module reads it at manifest-build time.
      config.contentFile = ./scanning-rules.toml;

      # POST /api/v2/secret-scanning/data-sources/{platform}
      #
      # Three platforms: github, gitlab, bitbucket.
      dataSources = {
        lab-repos = {
          platform = "github";
          connectionId = "lab-github";
          description = "Everything under the lab org";
          isAutoScanEnabled = true;   # default true
          config.includeRepos = [ "*" ]; # default ["*"], 1-100, max 256 each
        };

        # gitlab's config is an anyOf on scope, and the two branches take
        # different required fields — group needs groupId, project needs
        # projectId, both numbers rather than strings.
        gitlab-group = {
          platform = "gitlab";
          connectionId = "lab-gitlab";
          config = {
            scope = "group";          # "group" | "project"
            groupId = 12345;
            groupName = "lab";
            includeProjects = [ "*" ];
          };
        };
      };

      # Findings are results, not declarations. They are triaged, and triage
      # is a human verdict recorded after the fact:
      #
      #   PATCH /api/v2/secret-scanning/findings
      #     [ { findingId, status, remarks } ]   max 500
      #     status: resolved | unresolved | false-positive | ignore
      #
      # Declaring a finding's status would mean pinning a verdict by UUID in
      # a Nix file, which is a worse place for it than the tool that has the
      # finding in front of it. Deliberately absent.
      #
      # What IS declarable is the suppression list, and it lives on the
      # project rather than here — `secretDetectionIgnoreValues` in
      # 30-project.nix. Literal values the scanner will not flag. Note that
      # this is a list of the actual strings, so a suppression list is itself
      # a list of things that look like secrets.
    };
  };
}
