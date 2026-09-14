# The home-manager options `hm-agent.nix` uses, and nothing else.
#
# home-manager is not an input to this flake and should not become one: the
# agent module borrows exactly two of its options, and taking the whole project
# as an input to evaluate a module standalone would be a large dependency
# bought for a small reason.
#
# So this stub declares those two. That is not a shortcut — it is the module's
# entire contract with home-manager written down where it can be checked. If
# `hm-agent.nix` ever reaches for a third option, evaluation against this stub
# fails, and the failure is the notification.
#
# Used by `checks.hm-agent` and by the options documentation, which is why it
# lives here rather than inline in flake.nix. Both need the same stub, and two
# copies of it would drift in the direction of whichever one was edited last.
#
# It is deliberately NOT in the documented-module list in nix/docs: these are
# home-manager's options, not this flake's, and documenting them here would
# claim a surface nixfisical does not own.
{ lib, ... }:

{
  options.systemd.user.services = lib.mkOption {
    type = lib.types.attrsOf (lib.types.attrsOf lib.types.anything);
    default = { };
  };

  options.assertions = lib.mkOption {
    type = lib.types.listOf lib.types.unspecified;
    default = [ ];
  };
}
