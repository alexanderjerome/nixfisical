# nixfisical server module — run a self-hosted Infisical instance.
#
# nixpkgs ships only the Infisical *client* (`pkgs.infisical`, the Go CLI).
# There is no `services.infisical`, so every self-hoster ends up hand-rolling
# an OCI container. This module is that hand-rolled container, done once and
# declaratively — with a `native` backend behind the same option surface for
# when the server package lands (see `vendor/infisical` and docs/native.md).
#
# Secrets never appear in the Nix store. ENCRYPTION_KEY, AUTH_SECRET and
# DB_CONNECTION_URI (which embeds the Postgres password) are read at start
# from `environmentFiles` — point those at `config.sops.templates.*.path`,
# an agenix path, or anything else that lands a root-only env file on the
# host. The module refuses to start without them rather than booting an
# instance with a default encryption key.
{ config, pkgs, lib, ... }:

let
  inherit (lib) mkEnableOption mkOption mkIf types;
  cfg = config.services.infisical;

  # Non-secret settings only. Anything sensitive goes through environmentFiles,
  # which systemd reads at start and never writes to the store.
  baseEnvironment = {
    NODE_ENV = "production";
    PORT = toString cfg.port;
    HOST = cfg.host;
    SITE_URL = cfg.siteUrl;
    TELEMETRY_ENABLED = lib.boolToString cfg.telemetry.enable;
  }
  // lib.optionalAttrs (cfg.redis.url != null) { REDIS_URL = cfg.redis.url; }
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
        container runtime. Not yet implemented — the packaging work happens
        against the vendored upstream checkout in this repo. Selecting it
        produces a clear evaluation error rather than a broken host.
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
      default = "latest-postgres";
      description = ''
        Image tag for the `oci` backend. Pin this to a release tag in
        production — `latest-postgres` will silently move under you and
        Infisical runs database migrations on start.
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

    environmentFiles = mkOption {
      type = types.listOf types.path;
      default = [ ];
      example = lib.literalExpression ''[ config.sops.templates."infisical-env".path ]'';
      description = ''
        Files of `KEY=value` lines loaded at start. At minimum these must
        supply `ENCRYPTION_KEY`, `AUTH_SECRET` and `DB_CONNECTION_URI`.
        Keep them root-only and out of the Nix store.
      '';
    };

    extraEnvironment = mkOption {
      type = types.attrsOf types.str;
      default = { };
      description = ''
        Additional non-secret environment variables. These land in the Nix
        store — never put credentials here, use `environmentFiles`.
      '';
    };

    redis.url = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "redis://10.0.0.10:6379";
      description = ''
        Redis/Valkey connection URL. Infisical requires one. Leave null only
        if you are supplying `REDIS_URL` through `environmentFiles` (which is
        what you want when the URL carries a password).
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
            services.infisical.environmentFiles is empty. Infisical needs
            ENCRYPTION_KEY, AUTH_SECRET and DB_CONNECTION_URI, all of which
            are secrets and must not be written to the Nix store. Point this
            at a sops-nix template or equivalent.
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

            Packaging the Infisical server (a Node/TypeScript app with a
            Knex migration step) is tracked in this repo against the vendored
            upstream checkout; see docs/native.md. Use backend = "oci" until
            it lands.
          '';
        }
      ];

      networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];
    }

    (mkIf (cfg.backend == "oci") {
      virtualisation.oci-containers.containers.infisical = {
        image = "${cfg.image}:${cfg.imageTag}";
        autoStart = true;
        environment = baseEnvironment;
        environmentFiles = cfg.environmentFiles;
        # Host networking keeps the published port honest when the container
        # runtime and a host reverse proxy disagree about loopback, and means
        # `port` above is the port actually listened on.
        extraOptions = [ "--network=host" ];
      };
    })
  ]);
}
