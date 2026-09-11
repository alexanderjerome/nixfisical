# nixfisical export module — adds `infisical` to every sops.secrets entry.
#
# The NixOS module system merges submodule option-sets across every module
# that targets the same option. So this re-declares `sops.secrets` with ONLY
# a type contributing one new option. sops-nix's own declaration (its
# defaults, descriptions, and the rest of its options) is untouched and still
# wins; this adds a field and nothing else.
#
# IT IS NOT FREE, and an earlier version of this comment said it was. sops-nix
# builds its on-host manifest with
#
#   builtins.toJSON { secrets = builtins.attrValues cfg.secrets; ... }
#
# (modules/sops/manifest-for.nix) — the WHOLE submodule, fields it has never
# heard of included. So `"infisical": null` lands in manifest.json for every
# secret the moment this module is imported, which moves the manifest's store
# path, which moves the host's toplevel. Importing this fleet-wide rebuilds
# every host that uses sops, annotated or not; changing one annotation
# afterwards rebuilds that host. Measured, not assumed: on a 17-host fleet the
# import moved every toplevel except the three hosts with no sops secrets.
#
# What IS true: sops-nix never *reads* the field. `sops-install-secrets` is Go
# and ignores unknown JSON keys, and its `-check-mode=sopsfile` validation
# accepts the manifest, so the resulting activation is a no-op — same secrets,
# same paths, same owners. The cost is a deploy, not a behaviour change.
#
# Two things to plan around:
#
#   * Import this in the same change as your first annotations, not ahead of
#     them "to be safe". Importing alone buys a fleet-wide redeploy and
#     nothing else.
#   * The routing metadata (project, folder, environment, groups) ends up in a
#     world-readable /nix/store path on each host. It names no values, and the
#     encrypted SOPS file is already sitting next to it, but if a folder name
#     is itself sensitive, that is where it leaks.
#
# A secret with no `infisical` (the default) is infra-only: it stays in SOPS,
# reaches the host, and is never mirrored to Infisical. Exporting is opt-in
# per secret, which is the safe default — a fleet's SOPS file is full of
# things developers must not see.
#
# Import this on every host whose secrets you want to be exportable, then
# render with `nixfisical.lib.manifestOf self.nixosConfigurations`.
{ lib, ... }:

let
  inherit (lib) mkOption types;

  infisicalType = types.submodule {
    options = {
      project = mkOption {
        type = types.str;
        description = ''
          Infisical project the secret lands in. This is the hard access
          boundary — group grants are per project — so it has no default.
        '';
        example = "bitcoin-nodes";
      };

      folder = mkOption {
        type = types.str;
        default = "/";
        description = ''
          Absolute folder path within the project/environment. Ancestors are
          created automatically by `nixfisical sync`.
        '';
        example = "/mainnet";
      };

      environment = mkOption {
        type = types.str;
        default = "prod";
        description = ''
          Infisical environment slug. Must be URL-safe (`[a-z0-9-]+`) —
          it is interpolated into API paths and folder lookups.
        '';
      };

      name = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Secret name as developers see it in Infisical. Defaults to the last
          segment of the SOPS key path, so
          `services/bitcoin/rpc_password` becomes `rpc_password`.
        '';
        example = "RPC_PASSWORD";
      };

      groups = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          Groups granted read access. Carried into the manifest for the
          access-reconciliation step; an empty list means the secret is
          exported but only administrators can read it.
        '';
        example = [ "developers" ];
      };
    };
  };
in
{
  options.sops.secrets = mkOption {
    type = types.attrsOf (types.submodule {
      options.infisical = mkOption {
        type = types.nullOr infisicalType;
        default = null;
        description = ''
          Developer-facing export metadata. When set, this secret is emitted
          into the Infisical manifest at the given project / environment /
          folder, scoped to `groups`. `null` (the default) means infra-only:
          the secret stays in SOPS and never reaches Infisical.
        '';
      };
    });
  };
}
