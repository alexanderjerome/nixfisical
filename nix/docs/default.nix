# nixfisical/nix/docs — the option surface and the CLI surface, rendered.
#
# `nix build github:jeirslab/nixfisical#docs` produces a directory an agent (or
# a person) can read without a checkout, without credentials, and without an
# Infisical instance to point at:
#
#   index.md         what this flake provides and which piece answers what
#   options.json     every option this repo declares, machine-readable
#   options.md       the same, rendered
#   commands.json    the CLI's full command tree, machine-readable
#   commands.md      the same, rendered
#
# WHY A DERIVATION AND NOT A SERVER. "What options exist and what do they
# mean" is the most common question asked of this flake and the one that needs
# the least machinery to answer: no process, no network, no authentication. A
# server re-serving static prose is a thing that can drift from the modules it
# describes. This cannot — it is generated from the module system itself, so an
# option added without a description is a hole visible here, and an option
# renamed moves here in the same commit.
#
# The MCP server (`nix run .#mcp`) is deliberately the complement of this file
# and shares nothing with it: it answers only questions that need a live
# instance. If a question can be answered by a file, it is answered here.
{ lib
, pkgs
, nixpkgs
, nixfisical
}:

let
  # The modules whose options are this flake's public surface.
  #
  # An explicit list rather than "every file under nix/modules", because
  # nix/modules also holds `hm-stub.nix`, whose two options belong to
  # home-manager. Documenting those would claim a surface nixfisical does not
  # own, and the failure mode of a path-prefix match is that it silently
  # starts claiming one the day a helper module is added.
  documented = [
    "server.nix"
    "export.nix"
    "inject.nix"
    "hm-agent.nix"
  ];

  # Matched on the path's tail, not its basename. nixpkgs has a `server.nix` of
  # its own (services/security/firezone), and a basename match pulled all
  # nineteen of `services.firezone.*` into this flake's documented surface —
  # silently, because a docs page with too much on it looks like a docs page.
  ours = f: d: lib.hasSuffix "/nix/modules/${f}" (toString d);

  isOurs = opt:
    lib.any (d: lib.any (f: ours f d) documented) (opt.declarations or [ ]);

  repoUrl = "https://github.com/jeirslab/nixfisical";

  # Declarations arrive as store paths (`/nix/store/<hash>-source/nix/modules/
  # server.nix`), which are useless to a reader and change on every commit —
  # a docs output that churns on content-free rebuilds is one nobody diffs.
  #
  # An attrset, not a relative string. The renderer treats a bare relative path
  # as nixpkgs-relative and hyperlinks it into NixOS/nixpkgs, so every option
  # here was being attributed to a file in nixpkgs that does not exist. The
  # `{ name; url; }` form is the documented way to say "somewhere else".
  relativise = d:
    let match = lib.findFirst (f: ours f d) null documented; in
    if match == null then toString d else {
      name = "nix/modules/${match}";
      url = "${repoUrl}/blob/main/nix/modules/${match}";
    };

  # An option tree pruned to the options `isOurs` accepts.
  #
  # Pruned BEFORE `nixosOptionsDoc` rather than filtered out of its output,
  # because the doc builder forces every `default`, `example` and type
  # description it is handed. The NixOS evaluation below carries all of
  # nixpkgs' options with it; forcing those is minutes of work for a result
  # that is then thrown away, and any one of them that throws on a bare
  # evaluation takes the whole build with it.
  prune = attrs:
    lib.filterAttrs (_: v: v != null) (lib.mapAttrs
      (_: v:
        if lib.isOption v then (if isOurs v then v else null)
        else if builtins.isAttrs v && !(lib.isDerivation v)
        then (let sub = prune v; in if sub == { } then null else sub)
        else null)
      attrs);

  mkDoc = options: pkgs.nixosOptionsDoc {
    options = prune (builtins.removeAttrs options [ "_module" ]);
    transformOptions = opt: opt // {
      declarations = map relativise (opt.declarations or [ ]);
    };
    # These modules are documented, not deprecated. A warning here would be
    # about an option we wrote; it should fail the docs build only once there
    # is a policy about what it means, and there is not one yet.
    warningsAreErrors = false;
  };

  # The NixOS modules are evaluated inside a real NixOS configuration rather
  # than with a hand-written stub. They are ordinary service modules — they
  # reach for `systemd`, `users`, `networking` — and stubbing that surface
  # would be maintaining a second, worse copy of nixpkgs' option set. Only
  # `.options` is read, so nothing in `.config` is forced and the absence of a
  # bootloader, a filesystem or a hostname never comes up.
  nixosOptions = (nixpkgs.lib.nixosSystem {
    modules = [
      ../modules/server.nix
      ../modules/export.nix
      ../modules/inject.nix
      { nixpkgs.pkgs = pkgs; }
    ];
  }).options;

  # The home-manager module cannot be, for the reason in hm-stub.nix.
  hmOptions = (lib.evalModules {
    modules = [
      ../modules/hm-agent.nix
      ../modules/hm-stub.nix
      { _module.args.pkgs = pkgs; }
    ];
  }).options;

  nixosDoc = mkDoc nixosOptions;
  hmDoc = mkDoc hmOptions;

  index = pkgs.writeText "nixfisical-docs-index.md" ''
    # nixfisical

    Declarative Infisical for NixOS fleets. SOPS stays the source of truth;
    Infisical is the developer-facing view of it.

    This directory is generated by `nix build github:jeirslab/nixfisical#docs`
    and is the offline half of this flake's agent surface. It describes what
    can be *declared*. For what is true of a running instance right now — which
    projects exist, what a sync would change, what a prune would delete — run
    the MCP server (`nix run github:jeirslab/nixfisical#mcp`), which is the
    only piece that talks to an instance.

    ## Files

    | | |
    | --- | --- |
    | `options.json` / `options.md` | every option the NixOS and home-manager modules declare |
    | `commands.json` / `commands.md` | the `nixfisical` CLI's full command tree |

    `options.json` is keyed by dotted option name and carries `type`,
    `default`, `example`, `description` and the declaring file.
    `commands.json` mirrors the CLI's own `--help`, generated from it.

    ## Three ways a secret reaches a filesystem

    They are for different machines, and picking the wrong one is the mistake
    this table exists to prevent.

    | | | |
    | --- | --- | --- |
    | `nixosModules.export` | operator | Annotate a `sops.secrets` entry so `nixfisical sync` mirrors it into Infisical. Nothing is fetched; this is the declaration side. |
    | `nixosModules.inject` | server | The host fetches its own secrets from the instance at boot instead of through sops-nix. A different trust model, not a better one. |
    | `homeManagerModules.agent` | laptop | A login session polls the instance and re-renders templates when a secret changes. |

    Only the last one polls. On a server, a secret changing under a running
    process should be a restart the operator ordered.

    ## Before operating an instance

    Four things that are silent when they go wrong, and are the reason the
    `/nixfisical:operate` skill exists alongside these files:

    - **`sync` prunes.** Deleting a `mkInfisical` annotation deletes the secret
      from Infisical on the next run. Always `--dry-run` first; it names every
      deletion.
    - **`sync` before `sync-access`.** `sync-access` grants a group access to a
      project, so the project has to exist and `sync` is what creates it. Run
      the other way round, a first convergence grants nothing and reports no
      error.
    - **`source` decides direction.** `source = "sops"` means `sync` pushes the
      local value up; `source = "infisical"` means it does not, and `import`
      pulls the instance's value down instead. A typo in that field reads as
      SOPS-owned and overwrites a value this fleet did not author.
    - **Group creation is licence-gated.** `nixfisical license` says so before a
      deploy finds out from a 400.
  '';

in
pkgs.runCommand "nixfisical-docs"
{
  nativeBuildInputs = [ pkgs.jq nixfisical ];
  meta = {
    description = "Generated option and CLI reference for nixfisical";
    longDescription = ''
      The offline half of nixfisical's agent surface: every declarable option
      and every CLI command, generated from the module system and the command
      tree rather than written alongside them.
    '';
  };
} ''
  mkdir -p "$out"
  cp ${index} "$out/index.md"

  # One file per audience-facing question, not one per evaluation. A reader
  # asking "what can I set" should not have to know that two different module
  # systems answered.
  jq -n \
    --slurpfile nixos ${nixosDoc.optionsJSON}/share/doc/nixos/options.json \
    --slurpfile hm ${hmDoc.optionsJSON}/share/doc/nixos/options.json \
    '{ nixos: $nixos[0], homeManager: $hm[0] }' > "$out/options.json"

  {
    echo "# nixfisical options"
    echo
    echo "Generated. Do not edit — edit the module and rebuild \`#docs\`."
    echo
    echo "## NixOS modules"
    echo
    cat ${nixosDoc.optionsCommonMark}
    echo
    echo "## home-manager modules"
    echo
    cat ${hmDoc.optionsCommonMark}
  } > "$out/options.md"

  # Generated from the live click tree, so a command that exists and a command
  # that is documented are the same set by construction.
  nixfisical docs --format json > "$out/commands.json"
  nixfisical docs --format markdown > "$out/commands.md"

  # A docs output that silently rendered nothing is worse than a failed build:
  # it looks like a flake with no options. These are the two evaluations that
  # can go quiet — a pruned-to-empty option tree reads as a clean success.
  for f in options.json commands.json; do
    [ -s "$out/$f" ] || { echo "docs: $f is empty" >&2; exit 1; }
  done
  [ "$(jq '.nixos | length' "$out/options.json")" -gt 0 ] \
    || { echo "docs: no NixOS options survived the prune" >&2; exit 1; }
  [ "$(jq '.homeManager | length' "$out/options.json")" -gt 0 ] \
    || { echo "docs: no home-manager options survived the prune" >&2; exit 1; }
''
