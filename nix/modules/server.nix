# nixfisical server module — run a self-hosted Infisical instance.
#
# nixpkgs ships only the Infisical *client* (`pkgs.infisical`, the Go CLI).
# There is no `services.infisical`, so every self-hoster ends up hand-rolling
# an OCI container. This module is that hand-rolled container, done once and
# declaratively — with a `native` backend behind the same option surface for
# when the server package lands (see docs/native.md).
#
# Secrets never appear in the Nix store. Anything sensitive is read at start
# from `environmentFiles` — point those at `config.sops.templates.*.path`, an
# agenix path, or anything else that lands a root-only env file on the host.
#
# ## Why almost every option below defaults to null
#
# For the `oci` backend, non-secret settings become `-e KEY=value` and
# `environmentFiles` becomes `--env-file`. Docker and Podman resolve those in
# that order: **`-e` wins over `--env-file`**. So any value this module emits
# by default could not be overridden by a secret file — the env file would be
# read and silently ignored.
#
# That is a real hazard here, because which settings count as secret differs
# per deployment. A fleet that keeps SMTP_HOST and SMTP_USERNAME in sops (a
# perfectly reasonable choice) must be able to supply them through
# `environmentFiles`. So the rule is: this module emits a variable only when
# you explicitly set the matching option. Leave it null and the variable is
# absent from the store entirely, free for an env file to define.
{ config, pkgs, lib, ... }:

let
  inherit (lib) mkEnableOption mkOption mkIf types optionalAttrs optionalString;
  cfg = config.services.infisical;

  db = cfg.database;
  redis = cfg.redis;
  smtp = cfg.smtp;

  # Upstream (backend/src/lib/config/env.ts) declares DB_CONNECTION_URI with a
  # *default* composed from the discrete vars:
  #
  #   postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}
  #
  # So an explicit DB_CONNECTION_URI wins and the discrete vars are ignored.
  # The two shapes are mutually exclusive in practice, and the assertion below
  # makes that explicit rather than letting one silently shadow the other.
  #
  # Discrete is the better default: a connection URI embeds the password, so it
  # can only ever come from an env file, whereas host/port/user/name are not
  # secret and belong in the configuration you can read and review. Only
  # DB_PASSWORD then has to come from `environmentFiles`.
  databaseEnvironment =
    if db.connectionUri != null then
      { DB_CONNECTION_URI = db.connectionUri; }
    else
      optionalAttrs (db.host != null)
        {
          DB_HOST = db.host;
          DB_PORT = toString db.port;
        }
      // optionalAttrs (db.user != null) { DB_USER = db.user; }
      // optionalAttrs (db.name != null) { DB_NAME = db.name; };

  # A CA certificate is public by nature, so unlike the rest of the DB
  # settings this one is safe to carry in the store.
  databaseExtraEnvironment =
    optionalAttrs (db.rootCert != null) { DB_ROOT_CERT = db.rootCert; }
    // optionalAttrs (db.poolMin != null) { DB_POOL_MIN = toString db.poolMin; }
    // optionalAttrs (db.poolMax != null) { DB_POOL_MAX = toString db.poolMax; };

  # `host`/`port` are a convenience for the common credential-free case; the
  # moment the connection needs a password in the URL you want `url = null`
  # and REDIS_URL from an env file instead.
  redisUrl =
    if redis.url != null then
      redis.url
    else
      optionalString (redis.host != null) "redis://${redis.host}:${toString redis.port}";

  redisEnvironment =
    optionalAttrs (redisUrl != "") { REDIS_URL = redisUrl; }
    // optionalAttrs (redis.username != null) { REDIS_USERNAME = redis.username; };

  smtpEnvironment = optionalAttrs smtp.enable (
    optionalAttrs (smtp.host != null) { SMTP_HOST = smtp.host; }
    // optionalAttrs (smtp.port != null) { SMTP_PORT = toString smtp.port; }
    // optionalAttrs (smtp.username != null) { SMTP_USERNAME = smtp.username; }
    // optionalAttrs (smtp.fromAddress != null) { SMTP_FROM_ADDRESS = smtp.fromAddress; }
    // optionalAttrs (smtp.fromName != null) { SMTP_FROM_NAME = smtp.fromName; }
    // optionalAttrs (smtp.heloHost != null) { SMTP_HELO_HOST = smtp.heloHost; }
    // optionalAttrs (smtp.ignoreTls != null) { SMTP_IGNORE_TLS = lib.boolToString smtp.ignoreTls; }
    // optionalAttrs (smtp.requireTls != null) { SMTP_REQUIRE_TLS = lib.boolToString smtp.requireTls; }
    // optionalAttrs (smtp.tlsRejectUnauthorized != null) {
      SMTP_TLS_REJECT_UNAUTHORIZED = lib.boolToString smtp.tlsRejectUnauthorized;
    }
  );

  # Assembled once and shared by every backend, so `native` inherits the whole
  # option surface for free when it lands.
  serverEnvironment = {
    NODE_ENV = "production";
    PORT = toString cfg.port;
    HOST = cfg.host;
    SITE_URL = cfg.siteUrl;
    TELEMETRY_ENABLED = lib.boolToString cfg.telemetry.enable;
  }
  // databaseEnvironment
  // databaseExtraEnvironment
  // redisEnvironment
  // smtpEnvironment
  // cfg.extraEnvironment;
in
{
  options.services.infisical = {
    enable = mkEnableOption "a self-hosted Infisical secrets-management server";

    backend = mkOption {
      type = types.enum [ "oci" "native" ];
      default = "oci";
      description = ''
        How the server runs.

        `oci` runs the upstream `infisical/infisical` container image. This is
        what upstream supports and what works today.

        `native` runs a Nix-built server as a plain systemd unit, with no
        container runtime. Not yet implemented; see docs/native.md. Selecting
        it produces a clear evaluation error rather than a broken host.

        Every option below is backend-agnostic — they describe the server's
        configuration, not how it is packaged.
      '';
    };

    package = mkOption {
      type = types.nullOr types.package;
      default = null;
      description = ''
        Server package for the `native` backend. Ignored by `oci`.
      '';
    };

    image = mkOption {
      type = types.str;
      default = "infisical/infisical";
      description = "Container image for the `oci` backend.";
    };

    imageTag = mkOption {
      type = types.str;
      default = "latest";
      example = "v0.165.8";
      description = ''
        Image tag for the `oci` backend.

        Pin this to a release tag (`v0.165.8`) in production. The default
        moves under you, and Infisical runs Knex migrations against its
        database on start, so a routine host reboot can migrate the schema.

        Do **not** use `latest-postgres`, which older Infisical self-hosting
        docs recommend and which was this module's previous default. The
        `-postgres` suffix dates from when Infisical also shipped a MongoDB
        variant. Upstream stopped publishing it: the tag still resolves, but
        it has not been rebuilt since 2025-08-08, so it is a silently frozen
        year-old image rather than a moving pointer. No `-postgres` tag
        appears anywhere in the most recent 100 tags (checked 2026-09-09).
      '';
    };

    host = mkOption {
      type = types.str;
      default = "0.0.0.0";
      description = "Address the server binds.";
    };

    port = mkOption {
      type = types.port;
      default = 8080;
      description = "Port the server listens on.";
    };

    siteUrl = mkOption {
      type = types.str;
      example = "https://infisical.example.com";
      description = ''
        Public URL the instance is reached at. Infisical bakes this into
        invite and password-reset links, so a wrong value produces mail that
        points nowhere.
      '';
    };

    database = {
      connectionUri = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Full `DB_CONNECTION_URI`, taking precedence over every discrete
          `database.*` option below.

          A Postgres URI embeds the password, so setting this here writes a
          credential to the Nix store. Prefer leaving it null and using the
          discrete options, or supply `DB_CONNECTION_URI` through
          `environmentFiles`. Use this option only for a genuinely
          credential-free URI, such as a unix-socket or peer-authenticated
          connection.
        '';
      };

      host = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "10.40.0.115";
        description = ''
          Postgres host. Setting this selects the discrete `DB_*` shape, in
          which only the password is secret and must come from
          `environmentFiles` as `DB_PASSWORD`.

          Leave null (and leave `connectionUri` null) to supply
          `DB_CONNECTION_URI` entirely through `environmentFiles`.
        '';
      };

      port = mkOption {
        type = types.port;
        default = 5432;
        description = ''
          Postgres port. Only emitted when `database.host` is set.
        '';
      };

      user = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "infisical";
        description = "Postgres role to connect as.";
      };

      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "infisical";
        description = "Postgres database name.";
      };

      rootCert = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Base64-encoded CA certificate for the Postgres connection
          (`DB_ROOT_CERT`). A CA certificate is public, so unlike the rest of
          the connection settings this is safe to keep in the store.
        '';
      };

      poolMin = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = ''
          Minimum connections in the primary pool. Null leaves upstream's
          default in place rather than pinning today's value.
        '';
      };

      poolMax = mkOption {
        type = types.nullOr types.int;
        default = null;
        description = ''
          Maximum connections in the primary pool. Null leaves upstream's
          default in place rather than pinning today's value.
        '';
      };
    };

    redis = {
      url = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "redis://10.40.0.116:6379";
        description = ''
          Redis/Valkey connection URL, taking precedence over
          `redis.host`/`redis.port`. Infisical requires a cache.

          Leave null when the URL carries a password — supply `REDIS_URL`
          through `environmentFiles` instead, or set `redis.host` here and
          `REDIS_PASSWORD` in the env file.
        '';
      };

      host = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "10.40.0.116";
        description = ''
          Redis/Valkey host. Composes a credential-free `REDIS_URL` with
          `redis.port`. Authentication, if any, goes through `redis.username`
          and a `REDIS_PASSWORD` entry in `environmentFiles`.
        '';
      };

      port = mkOption {
        type = types.port;
        default = 6379;
        description = "Redis/Valkey port. Only used when `redis.host` is set.";
      };

      username = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Redis ACL username (`REDIS_USERNAME`). The matching password is a
          secret and belongs in `environmentFiles` as `REDIS_PASSWORD`.
        '';
      };
    };

    smtp = {
      enable = mkEnableOption ''
        outbound email. Infisical needs SMTP for invitations, password resets
        and alerts; without it those flows fail at send time rather than at
        deploy time
      '';

      host = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          SMTP server hostname. Null leaves `SMTP_HOST` to
          `environmentFiles`, which is what you want if your fleet treats the
          relay host as sensitive.
        '';
      };

      port = mkOption {
        type = types.nullOr types.port;
        default = null;
        description = "SMTP port. Null leaves upstream's default (587).";
      };

      username = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          SMTP username. The password is always a secret: supply
          `SMTP_PASSWORD` through `environmentFiles`.
        '';
      };

      fromAddress = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "no-reply@example.com";
        description = "Envelope sender address for outbound mail.";
      };

      fromName = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "Infisical";
        description = "Sender display name. Null leaves upstream's default.";
      };

      heloHost = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Hostname announced in the SMTP HELO/EHLO greeting, when the relay
          requires something other than the machine's own name.
        '';
      };

      ignoreTls = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = "Set `SMTP_IGNORE_TLS`. Null leaves upstream's default.";
      };

      requireTls = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = "Set `SMTP_REQUIRE_TLS`. Null leaves upstream's default.";
      };

      tlsRejectUnauthorized = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = ''
          Set `SMTP_TLS_REJECT_UNAUTHORIZED`. Null leaves upstream's default
          (true). Turning this off accepts any certificate the relay presents.
        '';
      };
    };

    environmentFiles = mkOption {
      type = types.listOf types.path;
      default = [ ];
      example = lib.literalExpression ''[ config.sops.templates."infisical-env".path ]'';
      description = ''
        Files of `KEY=value` lines loaded at start, holding everything secret.

        `ENCRYPTION_KEY` and `AUTH_SECRET` are always required. Beyond those,
        supply whichever of these the deployment needs and did not set as an
        option above: `DB_PASSWORD` (or a whole `DB_CONNECTION_URI`),
        `REDIS_PASSWORD` (or a whole `REDIS_URL`), `SMTP_PASSWORD`, and
        `DB_READ_REPLICAS` — which is a JSON array of objects each carrying a
        full connection URI, so it is secret by construction and has no
        option here.

        These files are read by systemd at start and never enter the store.
        Keep them root-only.
      '';
    };

    extraEnvironment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = ''
        Additional non-secret environment variables, for the parts of
        Infisical's configuration this module does not model as options —
        Redis Sentinel and Cluster topologies, queue worker profiles, SSO and
        app-connection settings.

        These land in the Nix store, so never put credentials here; use
        `environmentFiles`. Note also that anything set here takes precedence
        over `environmentFiles`, so a key set in both resolves to this value.
      '';
    };

    telemetry.enable = mkEnableOption "upstream Infisical telemetry" // {
      default = false;
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Open `port` in the host firewall. Leave this off when the instance
        sits behind a reverse proxy on the same host, which is the usual
        shape — the proxy terminates TLS and Infisical speaks plain HTTP.
      '';
    };
  };

  config = mkIf cfg.enable (lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.environmentFiles != [ ];
          message = ''
            services.infisical.environmentFiles is empty. Infisical needs at
            least ENCRYPTION_KEY and AUTH_SECRET, plus a database credential.
            All of those are secrets and must not be written to the Nix
            store. Point this at a sops-nix template or equivalent.
          '';
        }
        {
          assertion = !(db.connectionUri != null && db.host != null);
          message = ''
            services.infisical.database: `connectionUri` and `host` are both
            set. Infisical derives DB_CONNECTION_URI from the discrete DB_*
            variables only when DB_CONNECTION_URI is unset, so `host`, `port`,
            `user` and `name` would be silently ignored here. Set one shape or
            the other.
          '';
        }
        {
          assertion = !(redis.url != null && redis.host != null);
          message = ''
            services.infisical.redis: `url` and `host` are both set. `url`
            takes precedence, so `host` and `port` would be silently ignored.
            Set one or the other.
          '';
        }
        {
          assertion = cfg.backend == "oci" -> config.virtualisation.oci-containers.backend != null;
          message = "services.infisical: the `oci` backend needs virtualisation.oci-containers.backend set (e.g. \"docker\" or \"podman\").";
        }
        {
          assertion = cfg.backend != "native";
          message = ''
            services.infisical.backend = "native" is not implemented yet.

            Packaging the Infisical server (a Node/TypeScript app with a Knex
            migration step) is tracked in docs/native.md. Use backend = "oci"
            until it lands; every other option carries over unchanged.
          '';
        }
      ];

      networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
    }

    (mkIf (cfg.backend == "oci") {
      virtualisation.oci-containers.containers.infisical = {
        image = "${cfg.image}:${cfg.imageTag}";
        autoStart = true;
        environment = serverEnvironment;
        environmentFiles = cfg.environmentFiles;
        # Host networking keeps the published port honest when the container
        # runtime and a host reverse proxy disagree about loopback, and means
        # `port` above is the port actually listened on.
        extraOptions = [ "--network=host" ];
      };
    })
  ]);
}
