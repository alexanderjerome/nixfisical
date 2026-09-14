# nixfisical hm-agent module — Infisical's own agent, as a home-manager
# `systemd.user` service, for developer machines.
#
# This is the third way a secret can reach a filesystem in this repo, and the
# three are for different machines:
#
#   export   SOPS is the truth, Infisical gets a copy. Operator-side.
#   inject   a NixOS host fetches its own secrets at boot. Server-side.
#   agent    a developer's login session keeps a rendered file up to date.
#
# Only the last one is a daemon that polls, and that is deliberate. On a
# server, a secret changing under a running process is a problem to be handled
# by a restart the operator ordered; on a laptop, a `.env` going stale is a
# developer running yesterday's credentials against today's instance and
# filing a bug about it. Polling is the right answer to the second and the
# wrong answer to the first, so this module is home-manager only. There is no
# NixOS counterpart and adding one would be a mistake.
#
# It wraps the UPSTREAM Go binary (`pkgs.infisical`), not anything in this
# repo. `nixfisical-agent` is a Python oneshot that places whole secret values
# at paths; this renders Go templates and watches them. They are not
# alternatives and a machine can run both.
#
# WHAT IS AND IS NOT IN THE STORE. The generated config holds the instance
# URL, project ids, environment slugs, destination paths, and the *paths* of
# the credential files. It holds no credential and no secret value. Templates
# are programs, not data: a template says "fetch this coordinate", and the
# fetch happens in the agent against the live instance. The rendered output is
# the only place a value appears, and that is outside the store, in the
# developer's own tree.
{ config, lib, pkgs, ... }:

let
  inherit (lib) mkEnableOption mkIf mkOption types;

  cfg = config.programs.nixfisical.agent;

  nixfisicalLib = import ../lib { inherit lib; };

  yamlFormat = pkgs.formats.yaml { };

  templateType = types.submodule {
    options = {
      source = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = ''
          A Go `text/template` file, rendered by the agent against the live
          instance. This is the form to reach for: a real template has
          conditionals and shapes the output for the tool that reads it, and
          that belongs in a file under version control, not in a Nix string.

          A path in the Nix language is copied into the store, so the template
          becomes world-readable on this machine. That is correct — it names
          coordinates and contains no values — but a template whose *folder
          names* are themselves sensitive leaks them here.

          Exactly one of `source`, `content` and `dotenv.enable` may be set.
        '';
        example = lib.literalExpression "./templates/work.env.tmpl";
      };

      content = mkOption {
        type = types.nullOr types.lines;
        default = null;
        description = ''
          The template inline, for the cases too small to deserve a file.
          `nixfisical.lib.mkDotenvTemplate` returns a string suitable here.

          Written to the store as a file and handed to the agent as a path,
          exactly like `source` — so this carries the same store visibility,
          and byte-for-byte what you wrote reaches the template engine.
        '';
      };

      dotenv = {
        enable = mkEnableOption "rendering this template as a dotenv dump of one folder";

        secretPath = mkOption {
          type = types.str;
          default = "/";
          description = "Folder within the project/environment to dump.";
          example = "/backend";
        };

        recursive = mkOption {
          type = types.bool;
          default = false;
          description = ''
            Include sub-folders, flattened. Off, because two folders holding
            the same key name collapse into one line and nothing says which
            one won.
          '';
        };

        expandSecretReferences = mkOption {
          type = types.bool;
          default = true;
          description = ''
            Resolve `''${OTHER_SECRET}` references before writing. On, matching
            the agent's own default — an unresolved reference reaches the
            application as a literal dollar-brace string.
          '';
        };
      };

      destination = mkOption {
        type = types.str;
        description = ''
          Absolute path the rendered output is written to. Parent directories
          are created by this module, not by the agent — upstream does a bare
          `os.Create`, which fails on a missing directory.
        '';
        example = "/home/dev/src/work/.env";
      };

      mode = mkOption {
        type = types.str;
        default = "0600";
        description = ''
          Octal mode of the rendered file.

          Enforced by this module, and it has to be: upstream's `os.Create`
          leaves a new file at 0644 minus the umask, which on a shared machine
          is every credential the developer has, readable by everyone. The
          pre-start creates the file at this mode if it is absent and chmods
          it if it is not — `os.Create` truncates an existing file without
          touching its mode, so setting it once holds for every later render.
        '';
      };

      pollingInterval = mkOption {
        type = types.str;
        default = "60s";
        description = ''
          How often the agent re-fetches this template's coordinates. Upstream
          defaults to 5m; this defaults lower because the entire reason to run
          the agent on a laptop is not noticing that a secret rotated.

          Every template polls on its own timer, so N templates against one
          project is N times the request rate. Raise it for the ones that do
          not change.
        '';
        example = "5m";
      };

      onChange = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Shell command run after the rendered output **changes**.

          Two things upstream does here that are easy to be surprised by, and
          neither is worked around because both are the agent's behaviour and
          hiding them would only move the surprise:

          It does not run on the first render. The agent writes the file at
          startup and skips the command, so a service that needs reloading
          after the file appears must be ordered after this unit rather than
          hung off this hook.

          It runs under `$SHELL`, not `sh`. This module pins `SHELL` in the
          unit environment so the command is POSIX regardless of what the
          developer's login shell is — write `sh`, and it stays `sh`.
        '';
        example = "systemctl --user restart my-dev-server.service";
      };

      onChangeTimeout = mkOption {
        type = types.ints.unsigned;
        default = 30;
        description = ''
          Seconds before `onChange` is killed. Zero means no timeout, which on
          a polling daemon means one hung command stops that template being
          re-rendered for the rest of the session.
        '';
      };
    };
  };

  projectType = types.submodule {
    options = {
      projectId = mkOption {
        type = types.str;
        description = ''
          The project's UUID, as it appears in the instance URL. Not the
          slug: `listSecrets` — the function `dotenv` templates are built on —
          takes an id.

          An id is not a credential. It names a project to someone who already
          has an identity that may read it, which is why it can sit in a Nix
          file in a shared repo.
        '';
        example = "3a1e0c2e-1f4b-4f5e-9f1d-2b7c8e5a9d10";
      };

      environment = mkOption {
        type = types.str;
        default = "dev";
        description = ''
          Environment slug every `dotenv` template under this project reads.
          Defaults to `dev` rather than the `prod` used elsewhere in this
          repo: this module runs on a developer's machine, and the default
          that is wrong should be the one that fails closed.
        '';
      };

      templates = mkOption {
        type = types.attrsOf templateType;
        default = { };
        description = "Templates rendered from this project.";
      };
    };
  };

  # (project name, template name, template) for every template declared,
  # flattened once so the assertions and the config generation agree on what
  # the set is.
  allTemplates = lib.concatLists (lib.mapAttrsToList
    (projectName: project: lib.mapAttrsToList
      (templateName: template: {
        inherit projectName templateName project template;
        label = "${projectName}.${templateName}";
      })
      project.templates)
    cfg.projects);

  sourceCount = t:
    (if t.template.source != null then 1 else 0)
    + (if t.template.content != null then 1 else 0)
    + (if t.template.dotenv.enable then 1 else 0);

  # The template text for the two inline forms. `null` means the template
  # comes from a file and there is nothing to encode.
  inlineText = t:
    if t.template.dotenv.enable then
      nixfisicalLib.mkDotenvTemplate
        {
          inherit (t.project) projectId environment;
          inherit (t.template.dotenv) secretPath recursive expandSecretReferences;
        }
    else t.template.content;

  # Every template reaches the agent as `source-path`, including the inline
  # ones — an inline template is written to the store and its path handed
  # over, rather than embedded in the YAML as `template-content`.
  #
  # That is not just tidiness. A Go template is whitespace-significant (a
  # dotenv file's trailing newline decides whether some parsers see the last
  # pair), and a YAML block scalar is the wrong place to be arguing about
  # trailing whitespace. A file is byte-exact and the YAML holds a path.
  #
  # It also means the two forms are the same code path, so a bug in one is a
  # bug in both rather than a bug in whichever the author did not test.
  renderTemplate = t:
    let text = inlineText t; in
    {
      source-path =
        if text != null
        then "${pkgs.writeText "nixfisical-${t.projectName}-${t.templateName}.tmpl" text}"
        else "${t.template.source}";
      destination-path = t.template.destination;
      config = {
        polling-interval = t.template.pollingInterval;
      } // lib.optionalAttrs (t.template.onChange != null) {
        # `execute`, not `exec`. Upstream's own documented example says `exec`,
        # which the struct tag does not match, so it unmarshals to nothing and
        # the command silently never runs. This is the spelling in agent.go.
        execute = {
          command = t.template.onChange;
          timeout = t.template.onChangeTimeout;
        };
      };
    };

  agentConfig = {
    infisical = {
      address = cfg.address;
      exit-after-auth = cfg.exitAfterAuth;
      revoke-credentials-on-shutdown = cfg.revokeCredentialsOnShutdown;
    } // lib.optionalAttrs (cfg.retry.maxRetries != null) {
      retry-strategy = {
        max-retries = cfg.retry.maxRetries;
        base-delay = cfg.retry.baseDelay;
        max-delay = cfg.retry.maxDelay;
      };
    };

    auth = {
      type = "universal-auth";
      config = {
        client-id = "${cfg.auth.clientIdFile}";
        client-secret = "${cfg.auth.clientSecretFile}";
        # Underscores, unlike every other key in this file. That is upstream's
        # struct tag, not a typo here.
        remove_client_secret_on_read = cfg.auth.removeClientSecretOnRead;
      };
    };

    sinks = lib.optional (cfg.tokenSinkPath != null) {
      type = "file";
      config.path = cfg.tokenSinkPath;
    };

    templates = map renderTemplate allTemplates;
  };

  configFile = yamlFormat.generate "infisical-agent.yaml" agentConfig;

  # Everything the agent will write, created at the mode we want rather than
  # the mode `os.Create` would leave, before the agent gets to it.
  #
  # Three details that are each the difference between this working and this
  # being a hazard:
  #
  #   * `mkdir -p`, not `install -d -m`. The parent of a destination is
  #     usually a source tree the developer already owns, and `install -d`
  #     chmods a directory that already exists. Creating `~/src/api/.env`
  #     must not turn `~/src/api` into 0700.
  #   * the file is created inside a `umask 077` subshell rather than
  #     touched and then chmodded, so there is no window in which it exists
  #     at 0644 — which matters precisely because the next thing to happen
  #     is a secret being written into it.
  #   * the chmod runs unconditionally, so a mode that drifted is corrected
  #     on the next login instead of persisting silently.
  #
  # This holds for every later render: `os.Create` truncates an existing file
  # without touching its mode.
  #
  # `writeShellApplication` rather than `writeShellScript`, for the `set -eu`:
  # this runs as `ExecStartPre`, so a failure here has to stop the agent rather
  # than let it start and create the file itself at 0644. It also runs
  # shellcheck over generated shell, which is the only thing that reads it.
  prepareFile = path: mode: ''
    mkdir -p ${lib.escapeShellArg (builtins.dirOf path)}
    if [ ! -e ${lib.escapeShellArg path} ]; then
      ( umask 077; : > ${lib.escapeShellArg path} )
    fi
    chmod ${lib.escapeShellArg mode} ${lib.escapeShellArg path}
  '';

  prepare = pkgs.writeShellApplication {
    name = "nixfisical-agent-prepare";
    runtimeInputs = [ pkgs.coreutils ];
    text =
      lib.concatMapStrings
        (t: prepareFile t.template.destination t.template.mode)
        allTemplates
      + lib.optionalString (cfg.tokenSinkPath != null)
        (prepareFile cfg.tokenSinkPath "0600");
  };
in
{
  options.programs.nixfisical.agent = {
    enable = mkEnableOption "the Infisical agent as a user service";

    package = mkOption {
      type = types.package;
      default = pkgs.infisical;
      defaultText = lib.literalExpression "pkgs.infisical";
      description = ''
        Upstream's Go CLI, which carries the agent. Not `pkgs.nixfisical` —
        that is this repo's operator tooling and does not implement the
        template engine.
      '';
    };

    address = mkOption {
      type = types.str;
      description = "Base URL of the Infisical instance.";
      example = "https://infisical.example.com";
    };

    auth = {
      clientIdFile = mkOption {
        type = types.str;
        description = ''
          Path to a file holding this developer's universal-auth client id.

          A path, evaluated at run time by the agent, and a string rather than
          a `types.path` on purpose: a `types.path` would copy the file into
          the Nix store, which for the client secret below would be a
          credential published to every user on the machine. Keeping both
          options the same type keeps that mistake from being one character
          away.

          The agent reads `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` from the
          environment in preference to this file, so an exported variable
          silently wins over what is configured here.
        '';
        example = "/home/dev/.config/infisical/client-id";
      };

      clientSecretFile = mkOption {
        type = types.str;
        description = ''
          Path to a file holding the matching client secret. See
          `clientIdFile` for why this is a string.

          `nixfisical provision-host` mints these for machines; a developer's
          own identity is made in the UI or with `nixfisical`'s admin
          commands. Either way the file belongs in the developer's home at
          0600, delivered by whatever they already trust — not by this module,
          which would have to put it in the store to do so.
        '';
        example = "/home/dev/.config/infisical/client-secret";
      };

      removeClientSecretOnRead = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Delete the secret file after the agent reads it.

          Meant for a one-shot bootstrap where the credential is handed over
          once and must not persist. On a developer machine the agent restarts
          on every login, and the second login finds no credential — so this
          is off, and turning it on is a decision about how the file gets
          replaced, not a hardening toggle.
        '';
      };
    };

    tokenSinkPath = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = ''
        Write the access token the agent obtains to this path, so other tools
        — `infisical run`, a shell function, an editor plugin — can use the
        same session instead of holding their own credential.

        Created 0600 by this module. Off by default: it is a bearer token on
        disk, and a machine that has no second consumer gains nothing from it.
      '';
      example = "/home/dev/.config/infisical/token";
    };

    exitAfterAuth = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Render every template once and exit, instead of staying up and
        polling.

        Turns this module into the thing it exists not to be, and is here for
        exactly one case: a `Type=oneshot` render as part of some other unit's
        setup. Leaving it on and expecting rotation to reach the machine is
        the failure this option enables.
      '';
    };

    revokeCredentialsOnShutdown = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Revoke the obtained access token when the agent stops. Cleaner, and it
        makes a crash-and-restart loop mint a new token every cycle.
      '';
    };

    retry = {
      maxRetries = mkOption {
        type = types.nullOr types.ints.unsigned;
        default = null;
        description = ''
          Retries per failed request before the agent gives up on it. Null
          leaves upstream's own strategy in place, which is the right default
          — this exists for a flaky link, not for tuning.
        '';
        example = 5;
      };

      baseDelay = mkOption {
        type = types.str;
        default = "1s";
        description = "First backoff interval. Ignored unless `maxRetries` is set.";
      };

      maxDelay = mkOption {
        type = types.str;
        default = "30s";
        description = "Backoff ceiling. Ignored unless `maxRetries` is set.";
      };
    };

    projects = mkOption {
      type = types.attrsOf projectType;
      default = { };
      description = ''
        Projects this machine renders from. The attribute name is a label —
        it names the project in assertion messages and nothing else; the
        instance is addressed by `projectId`.

        Grouping by project is what makes a template short: a `dotenv`
        template inherits its project's id and environment rather than
        repeating them, so adding a second folder from the same project is
        three lines.
      '';
      example = lib.literalExpression ''
        {
          work = {
            projectId = "3a1e0c2e-1f4b-4f5e-9f1d-2b7c8e5a9d10";
            environment = "dev";
            templates = {
              backend = {
                dotenv.enable = true;
                dotenv.secretPath = "/backend";
                destination = "''${config.home.homeDirectory}/src/api/.env";
                onChange = "systemctl --user try-restart api-dev.service";
              };
              nginx = {
                source = ./templates/nginx.conf.tmpl;
                destination = "''${config.home.homeDirectory}/.config/dev-nginx.conf";
                mode = "0644";
              };
            };
          };
        }
      '';
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.address != "";
        message = "programs.nixfisical.agent.address must be set.";
      }
      {
        assertion = allTemplates != [ ];
        message = ''
          programs.nixfisical.agent is enabled but declares no templates. The
          agent would authenticate, render nothing, and sit in a poll loop
          over an empty list — a healthy-looking unit doing no work.
        '';
      }
      {
        assertion = lib.all (t: sourceCount t == 1) allTemplates;
        message =
          let
            bad = lib.filter (t: sourceCount t != 1) allTemplates;
          in
          ''
            programs.nixfisical.agent.projects: ${lib.concatMapStringsSep ", " (t: t.label) bad}
            must set exactly one of `source`, `content` and `dotenv.enable`.
            The agent picks between them in that order and ignores the rest
            silently, so two set is a template that renders and is not the one
            you wrote.
          '';
      }
      {
        assertion = lib.all (t: lib.hasPrefix "/" t.template.destination) allTemplates;
        message =
          let
            bad = lib.filter (t: !(lib.hasPrefix "/" t.template.destination)) allTemplates;
          in
          ''
            programs.nixfisical.agent.projects: ${lib.concatMapStringsSep ", " (t: t.label) bad}
            have a relative `destination`. The agent resolves it against its
            own working directory, which is the user's home only by accident.
          '';
      }
      {
        # Two templates writing one path is not an error the agent reports: it
        # renders both, on independent timers, and the file holds whichever
        # rendered last. Which one that is changes between polls.
        assertion =
          let
            paths = map (t: t.template.destination) allTemplates;
          in
          lib.length (lib.unique paths) == lib.length paths;
        message = ''
          programs.nixfisical.agent.projects: two templates share a
          `destination`. They render on separate timers, so the file's
          contents would depend on which poll landed last.
        '';
      }
    ];

    systemd.user.services.nixfisical-agent = {
      Unit = {
        Description = "Keep Infisical-backed files on this machine up to date";
        After = [ "network-online.target" ];
        Wants = [ "network-online.target" ];
      };

      Service = {
        ExecStartPre = "${prepare}/bin/nixfisical-agent-prepare";
        ExecStart = "${cfg.package}/bin/infisical agent --config ${configFile}";

        # `exitAfterAuth` renders once and exits 0. A `simple` unit that exits
        # is `failed` to anything ordering against it, and `Restart=on-failure`
        # would then not restart it while also not reporting success.
        Type = if cfg.exitAfterAuth then "oneshot" else "simple";
        RemainAfterExit = cfg.exitAfterAuth;

        Restart = if cfg.exitAfterAuth then "no" else "on-failure";
        RestartSec = 10;

        # The agent runs `onChange` through `$SHELL` when one is set, falling
        # back to `sh`. In a user unit `$SHELL` is inherited from the session
        # manager, so the same `onChange` string would be interpreted by bash
        # on one machine and fish on another. Pinning it makes the option mean
        # one thing.
        Environment = [ "SHELL=${pkgs.runtimeShell}" ];
      };

      Install = lib.mkIf (!cfg.exitAfterAuth) {
        WantedBy = [ "default.target" ];
      };
    };
  };
}
