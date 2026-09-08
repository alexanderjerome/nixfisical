# Both modules. Import this to get the server option surface and the
# `sops.secrets.<key>.infisical` annotation in one go.
#
# They are independent on purpose: a fleet that consumes a hosted Infisical
# wants `export.nix` alone, and a host that runs the server usually declares
# no exported secrets of its own. `flake.nixosModules` exposes each
# separately for exactly that reason.
{
  imports = [
    ./server.nix
    ./export.nix
  ];
}
