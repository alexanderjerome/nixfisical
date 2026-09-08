# nixfisical export module — adds `infisical` to every sops.secrets entry.
#
# The NixOS module system merges submodule option-sets across every module
# that targets the same option. So this re-declares `sops.secrets` with ONLY
# a type contributing one new option. sops-nix's own declaration (its
# defaults, descriptions, and the rest of its options) is untouched and still
# wins; this adds a field and nothing else. sops-nix never reads `infisical`,
# so the annotation is completely inert at deploy time — no activation
# behaviour changes, no secret moves, nothing to roll back.
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
