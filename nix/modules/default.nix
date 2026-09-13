# The server option surface and the `sops.secrets.<key>.infisical` annotation
# in one go.
#
# They are independent on purpose: a fleet that consumes a hosted Infisical
# wants `export.nix` alone, and a host that runs the server usually declares
# no exported secrets of its own. `flake.nixosModules` exposes each
# separately for exactly that reason.
#
# `inject.nix` is deliberately NOT here. Importing a module that only declares
# options is free, but this one is experimental and changes the host's trust
# model, so it is reached by naming it — `nixosModules.inject` — and never by
# importing "everything".
{
  imports = [
    ./server.nix
    ./export.nix
  ];
}
