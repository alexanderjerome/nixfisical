# nixfisical inject module — fetch this host's secrets from Infisical at boot.
#
# EXPERIMENTAL. This is the other direction from everything else in the repo,
# and it is a different trust model rather than a better one. Read
# `nixfisical/agent.py`'s docstring before enabling it; the short version:
#
#   * The host holds a credential that can *ask* for secrets, where sops-nix
#     gives it a key that can only decrypt what it was already handed. A
#     compromised host is now a read of everything its identity may read.
#   * Boot depends on the network. An unreachable instance is a failure to
#     start, which is the correct direction to fail but puts the secrets server
#     in the boot path of everything that consumes it.
#   * In exchange, rotation stops needing a deploy.
#
# It does not remove SOPS. The host still needs its universal-auth credentials
# from somewhere, and that somewhere is a SOPS file delivered by sops-nix —
# `nixfisical provision-host` puts them there. What changes is the count: one
# SOPS-delivered credential per host instead of one per secret.
#
# This module and `nixosModules.export` are not alternatives and can both be
# imported on one host. A secret is injected if it is listed here and exported
# if it is annotated there; nothing stops a value being both, and nothing
# should — a secret SOPS owns and Infisical mirrors is exactly what the export
# path is for, and one Infisical owns and this host reads is what this is for.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;

  cfg = config.services.nixfisical.inject;

  secretType = types.submodule ({ name, ... }: {
    options = {
      project = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Infisical project holding the secret. Resolved to a project id at
          run time through the host identity's own project listing, which
          doubles as the access check.

          May be omitted only if `projectId` is set instead. One of the two
          has to be, and an assertion says so.
        '';
        example = "platform";
      };

      projectId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Skip the name lookup and address the project by id.

          The escape hatch for an instance where a `no-access` identity may
          not list an organization's projects. Nothing else needs it, and an
          id in a Nix file is a value nobody can read — prefer `project`.
        '';
      };

      environment = mkOption {
        type = types.str;
        default = "prod";
        description = "Infisical environment slug.";
      };

      folder = mkOption {
        type = types.str;
        default = "/";
        description = "Absolute folder path within the project/environment.";
        example = "/grafana";
      };

      name = mkOption {
        type = types.str;
        description = "Secret name in Infisical.";
        example = "OIDC_CLIENT_SECRET";
      };

      path = mkOption {
        type = types.str;
        default = "${cfg.directory}/${name}";
        defaultText = lib.literalExpression ''"''${cfg.directory}/''${name}"'';
        description = ''
          Where the value is placed on this host. Defaults to the attribute
          name under `services.nixfisical.inject.directory`, which is a tmpfs:
          the value does not survive a reboot and is fetched again on the next
          one.
        '';
      };

      owner = mkOption {
        type = types.str;
        default = "root";
        description = "User that owns the placed file.";
      };

      group = mkOption {
        type = types.str;
        default = "root";
        description = "Group that owns the placed file.";
      };

      mode = mkOption {
        type = types.str;
        default = "0400";
        description = ''
          Octal mode of the placed file. Set and enforced on every run, not
          only when the value changes — ownership can drift without the secret
          rotating.
        '';
      };

      restartUnits = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Units restarted when this value **actually changes**, not when the
          configuration moves. Only units that are already active are
          restarted: a unit deliberately stopped stays stopped, and at boot the
          consumer has not started yet and reads the new value on its own.
        '';
        example = [ "grafana.service" ];
      };
    };
  });

  # World-readable, in the store, and containing no values — the same bargain
  # the export path makes with sops-nix's manifest.json. Folder and secret
  # names are visible to any local user; if a folder name is itself sensitive,
  # that is where it leaks.
  spec = pkgs.writeText "nixfisical-agent-spec.json" (builtins.toJSON {
    version = 1;
    url = cfg.url;
    organizationId = cfg.organizationId;
    secrets = lib.mapAttrsToList
      (_: secret: {
        inherit (secret) environment folder name path owner group mode;
        # The agent groups its listings by project *name*, so the field is
        # always populated. A secret addressed only by id gets the id as its
        # label: it never reaches a name lookup, and the coordinate in an
        # error message is then the only handle the operator was given.
        project = if secret.project != null then secret.project else secret.projectId;
        projectId = secret.projectId;
        restartUnits = secret.restartUnits;
      })
      cfg.secrets;
  });

  needsLookup = lib.any (secret: secret.projectId == null)
    (lib.attrValues cfg.secrets);

  unaddressed = lib.attrNames (lib.filterAttrs
    (_: secret: secret.project == null && secret.projectId == null)
    cfg.secrets);

  # Shared by the boot unit and the refresh unit, which differ only in
  # `RemainAfterExit` and in what starts them.
  agentService = {
    Type = "oneshot";
    ExecStart = lib.escapeShellArgs ([
      "${cfg.package}/bin/nixfisical-agent"
      "--spec"
      "${spec}"
      "--client-id-file"
      "${cfg.identity.clientIdFile}"
      "--client-secret-file"
      "${cfg.identity.clientSecretFile}"
    ] ++ lib.optionals cfg.cache.enable [ "--cache" cfg.cache.directory ]);

    # Runs as root: it chowns files to arbitrary service users and reads a
    # sops-nix secret that is root-only. Hardening it into a DynamicUser
    # would require handing back exactly those two capabilities.
    User = "root";
    # A boot-blocking unit that retries forever is a host that never
    # finishes booting. One attempt, fail closed, and the timer (or an
    # operator) tries again.
    Restart = "no";
  };
in
{
  options.services.nixfisical.inject = {
    enable = mkEnableOption "fetching this host's secrets directly from Infisical";

    package = mkOption {
      type = types.package;
      default = pkgs.nixfisical-agent or pkgs.nixfisical;
      defaultText = lib.literalExpression "pkgs.nixfisical-agent";
      description = ''
        The agent package. `nixfisical-agent` is the same source as
        `nixfisical` without the operator CLI and without the `sops` and `git`
        closure that wrapping it would pull onto this host.
      '';
    };

    url = mkOption {
      type = types.str;
      description = "Base URL of the Infisical instance.";
      example = "https://infisical.example.com";
    };

    organizationId = mkOption {
      type = types.str;
      default = "";
      description = ''
        Organization the projects live in. Needed to resolve project names to
        ids; not needed if every secret sets `projectId`. It is an identifier,
        not a credential — it is already in URLs and in the admin file.
      '';
    };

    identity = {
      clientIdFile = mkOption {
        type = types.path;
        description = ''
          File holding this host's universal-auth client id. Normally a
          sops-nix secret path: `config.sops.secrets."infisical/client_id".path`.
        '';
      };

      clientSecretFile = mkOption {
        type = types.path;
        description = ''
          File holding this host's universal-auth client secret, minted by
          `nixfisical provision-host`. Trailing whitespace is stripped — every
          way of producing this file can append a newline, and the resulting
          failure reads as "Invalid credentials" rather than as a stray byte.
        '';
      };
    };

    directory = mkOption {
      type = types.str;
      default = "/run/nixfisical";
      description = ''
        Default parent for placed secrets. On `/run`, so it is tmpfs: nothing
        this module fetches is written to disk unless `cache.enable` is on.
      '';
    };

    cache = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Keep a copy of the fetched values on disk, and serve from it when the
          instance cannot be reached.

          **This writes secret values to disk in plaintext**, which is the one
          property direct injection otherwise has over SOPS-at-rest. Off by
          default so that choice is made rather than inherited.

          It is worth making. Without it, a host that reboots during an
          instance outage comes up without the secrets its services need, and
          the outage becomes an outage of everything that depends on this host.
          With it, the same reboot serves values that may be stale — the agent
          says so loudly on every degraded run, because a fleet quietly running
          on month-old secrets is the failure this could produce silently.
        '';
      };

      directory = mkOption {
        type = types.str;
        default = "/var/lib/nixfisical/cache";
        description = "Where the plaintext fallback lives. Created 0700 root.";
      };
    };

    refreshInterval = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "hourly";
      description = ''
        A systemd `OnCalendar` expression to re-fetch on. Null (the default)
        means the agent runs at boot and on `systemctl start nixfisical-agent`
        only.

        Setting it is what makes "rotate without a deploy" actually reach the
        host unattended, and it is also what makes an instance outage a
        recurring alarm rather than a surprise at the next reboot.
      '';
    };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = ''
        Secrets to fetch and place. The attribute name is the default
        filename under `directory`.
      '';
      example = lib.literalExpression ''
        {
          "grafana-oidc" = {
            project = "platform";
            folder = "/grafana";
            name = "OIDC_CLIENT_SECRET";
            owner = "grafana";
            group = "grafana";
            restartUnits = [ "grafana.service" ];
          };
        }
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.url != "";
        message = "services.nixfisical.inject.url must be set.";
      }
      {
        assertion = unaddressed == [ ];
        message = ''
          services.nixfisical.inject.secrets: ${lib.concatStringsSep ", " unaddressed}
          name neither `project` nor `projectId`, so there is nothing to fetch
          them from.
        '';
      }
      {
        assertion = !needsLookup || cfg.organizationId != "";
        message = ''
          services.nixfisical.inject: at least one secret names its project by
          name, which has to be resolved to a project id at run time. Set
          `organizationId`, or give every secret a `projectId`.
        '';
      }
      {
        # Enabling the module and forgetting the secrets is a real mistake and
        # a silent one: the unit starts, succeeds at fetching nothing, and the
        # host looks provisioned. Better to say so at eval than to debug a
        # service reading a file that was never going to be written.
        assertion = cfg.secrets != { };
        message = ''
          services.nixfisical.inject is enabled but declares no secrets. The
          agent would authenticate, fetch nothing, and report success.
        '';
      }
    ];

    systemd.tmpfiles.rules = [
      # 0751: a service user can traverse to the one file it owns and cannot
      # enumerate the others. Same shape sops-nix uses for /run/secrets.
      "d ${cfg.directory} 0751 root root -"
    ] ++ lib.optional cfg.cache.enable
      "d ${cfg.cache.directory} 0700 root root -";

    systemd.services.nixfisical-agent = {
      description = "Fetch this host's secrets from Infisical";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # Consumers order against this unit, so it has to be settled before the
      # things that read its output start. `sysinit.target` is too early — the
      # network is not up — so this is the boundary that exists.
      before = [ "multi-user.target" ];

      serviceConfig = agentService // {
        # The placed secrets are the unit's output and they outlive the
        # process. Without this, a `systemctl status` on a correctly-working
        # host says "inactive (dead)", and ordering against it means nothing.
        RemainAfterExit = true;
      };
    };

    # The refresh runs the agent again rather than restarting the unit above,
    # and it is a separate unit for a reason that is easy to get wrong: a
    # `Type=oneshot` service with `RemainAfterExit=true` is `active (exited)`,
    # and a start job on an already-active unit returns -EALREADY and runs
    # nothing. A timer pointed straight at `nixfisical-agent.service` would
    # therefore fire on schedule, log success, and never fetch anything — the
    # "rotation without a deploy" headline, silently doing nothing.
    #
    # `systemctl restart nixfisical-agent.service` would work, but restarts
    # propagate: anything with `Requires=nixfisical-agent.service` restarts
    # too, every hour, which is the opposite of only restarting a consumer
    # whose value actually changed. So the refresh invokes the agent directly
    # and lets the agent's own change detection decide what to restart.
    systemd.services.nixfisical-agent-refresh = mkIf (cfg.refreshInterval != null) {
      description = "Re-fetch this host's secrets from Infisical";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # Deliberately no wantedBy: this unit is started by its timer and by
      # nothing else. It is also the right thing to `systemctl start` by hand
      # to pull a rotation down now.
      serviceConfig = agentService;
    };

    systemd.timers.nixfisical-agent-refresh = mkIf (cfg.refreshInterval != null) {
      description = "Re-fetch this host's secrets from Infisical";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.refreshInterval;
        # Every host in a fleet sharing a calendar expression means every host
        # in the fleet hitting the instance in the same second.
        RandomizedDelaySec = "5m";
        Persistent = true;
      };
    };
  };
}
