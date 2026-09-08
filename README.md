# nixfisical

Declarative [Infisical](https://infisical.com) for NixOS fleets.

nixpkgs ships the Infisical **client** (`pkgs.infisical`, the Go CLI) and
nothing else — no `services.infisical`, no server package. So everyone
self-hosting Infisical writes the same three things by hand: a container unit,
a one-shot bootstrap script, and a sync job that pushes secrets up from
wherever they actually live. This repo is those three things, written once.

It exists because a fleet's real secrets already live in SOPS, encrypted to
host keys, deployed by sops-nix. Infisical is the *developer-facing* view of a
subset of them. Keeping the two in agreement by hand does not scale and fails
in the direction that matters: a secret rotated in SOPS and redeployed leaves
a stale value in Infisical, and developers debug against a credential that
stopped working an hour ago.

**Status: experimental (v0.1.0).** The manifest and CLI are ported from a
working Ansible role driving a production fleet. The native (non-container)
server backend is not implemented yet — see [Roadmap](#roadmap).

## The idea

SOPS stays the source of truth. Each secret says, at its declaration site,
whether developers should see it and where it belongs:

```nix
{
  imports = [ nixfisical.nixosModules.export ];

  sops.secrets."services/bitcoin/rpc_password" = {
    restartUnits = [ "bitcoind.service" ];

    infisical = nixfisical.lib.mkInfisical {
      project = "bitcoin-nodes";     # the hard access boundary
      folder  = "/mainnet";
      groups  = [ "developers" ];
      name    = "RPC_PASSWORD";      # defaults to the last key segment
    };
  };
}
```

A secret with no `infisical` block is infra-only: it stays in SOPS and never
reaches Infisical. Exporting is opt-in per secret, because a fleet's SOPS file
is full of things developers must not see.

`nixfisical.lib.manifestOf` then walks every host and collects those
annotations into one manifest — structure only, no values, nothing decrypted
in the Nix store:

```json
[
  {
    "sopsKey":  "services/bitcoin/rpc_password",
    "sopsFile": "/fleet/nix/secrets/btc-nodes.yaml",
    "project":  "bitcoin-nodes",
    "environment": "prod",
    "folder":   "/mainnet",
    "name":     "RPC_PASSWORD",
    "groups":   ["developers"],
    "hosts":    ["btc-mainnet"]
  }
]
```

`nixfisical sync` reads that, decrypts each value **on your machine at run
time**, and converges the remote instance onto it: missing projects,
environments and folders get created, values get upserted, and secrets the
manifest no longer declares get pruned.

Because the declaration lives next to the secret, rotation is automatic. Change
the value in SOPS, redeploy, run the sync — Infisical follows. There is no
second list to remember to update.

## Quick start

```sh
# 1. Deploy the server (see "Running the server" below), then:

# 2. Bootstrap: create the superadmin, the org, and a `fleet-sync` machine
#    identity, and record all of it in a SOPS-encrypted admin file.
nix run github:alexanderjerome/nixfisical -- \
  --url https://infisical.example.com \
  --admin-file nix/secrets/infisical-admin.yaml \
  bootstrap --organization "Example" --git-commit

# 3. Render your fleet's manifest and check it before touching anything.
nix run .#infisical-manifest -- table
nix run .#infisical-manifest | nixfisical --url https://infisical.example.com sync --dry-run

# 4. Converge.
nix run .#infisical-manifest | nixfisical --url https://infisical.example.com sync
```

`--dry-run` reads everything and writes nothing, and it decrypts each value
before discarding it — so a renamed or rotated-away SOPS key fails the dry run
rather than the real sync. It reports exactly which secrets would be created,
updated, and **deleted**. Run it first.

## Flake outputs

| Output | What it is |
| --- | --- |
| `lib.mkInfisical` | Annotate a `sops.secrets` entry for export. |
| `lib.manifestOf` | `nixosConfigurations` → manifest list. |
| `lib.assertManifest` | Fail evaluation on a malformed manifest. |
| `mkManifestApp` | Wrap a manifest as a `nix run .#infisical-manifest` app. |
| `nixosModules.export` | Adds `sops.secrets.<key>.infisical`. |
| `nixosModules.server` | Runs a self-hosted instance. |
| `nixosModules.default` | Both of the above. |
| `packages.nixfisical` | The `nixfisical` CLI. |
| `overlays.default` | Puts `nixfisical` in your package set. |

Wiring the manifest app into a consumer flake:

```nix
packages.${system}.infisical-manifest = nixfisical.mkManifestApp {
  inherit pkgs;
  nixosConfigurations = self.nixosConfigurations;
};
```

## Running the server

```nix
{
  imports = [ nixfisical.nixosModules.server ];

  virtualisation.oci-containers.backend = "docker";

  services.infisical = {
    enable    = true;
    siteUrl   = "https://infisical.example.com";
    imageTag  = "v0.97.4-postgres";      # pin it; migrations run on start
    redis.url = "redis://10.0.0.10:6379";

    # ENCRYPTION_KEY, AUTH_SECRET and DB_CONNECTION_URI live here.
    environmentFiles = [ config.sops.templates."infisical-env".path ];
  };

  sops.templates."infisical-env".content = ''
    ENCRYPTION_KEY=${config.sops.placeholder."services/infisical/encryption_key"}
    AUTH_SECRET=${config.sops.placeholder."services/infisical/auth_secret"}
    DB_CONNECTION_URI=postgresql://infisical:${config.sops.placeholder."dbs/infisical/password"}@10.0.0.11:5432/infisical
  '';
}
```

Postgres and Redis are yours to provide — the module does not manage them, on
purpose: in a fleet they usually live on separate hosts with their own backup
and blast-radius story.

The module refuses to evaluate with an empty `environmentFiles` rather than
booting an instance with a default encryption key. Nothing secret is ever
written to the Nix store; `extraEnvironment` is for non-secret values only.

**Option namespace.** This module claims `services.infisical`. If you also
import [`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake),
which claims the same path, the two will conflict — pick one.

## The CLI

```
nixfisical bootstrap   initialise a fresh instance, record creds in SOPS
nixfisical sync        converge the instance onto a manifest
nixfisical validate    check a manifest offline (exit 2 on problems)
nixfisical status      is it reachable, and does the sync identity still work
```

Bootstrap is the destructive one, so it is guarded properly. If the admin file
already exists, it **logs in with the recorded sync identity** and exits
successfully if that works — so it is safe to run unconditionally as a
first-deploy step. If the file exists but the login fails, it stops and says
so instead of re-bootstrapping over a live instance; recovering is a
deliberate act, not a default. Rendering the admin file and encrypting it is
one step: if `sops --encrypt` fails, the plaintext is deleted before the error
propagates.

`--git-commit` commits the encrypted admin file (never pushes), so a
first-deploy run leaves the credentials tracked rather than sitting untracked
in a working tree waiting to be lost.

## What it does not do yet

**Access reconciliation.** The Ansible role this is ported from also created
groups and granted them per-project roles. On Infisical's free tier the group
API is plan-gated, so it did that with direct `INSERT`s into the Infisical
Postgres database. That is deliberately not ported — it is a workaround
against an undocumented schema, and it belongs behind a flag with its own
warning if it comes back. Today `groups` is carried through the manifest and
used for reporting only.

**Folder pruning.** Secrets are pruned; empty folders are left behind.

**Native server backend.** See below.

## Roadmap

- `services.infisical.backend = "native"` — run the server as a plain systemd
  unit with no container runtime, so the version is pinned by the flake and
  Knex migrations stop being something a reboot can trigger. Selecting it
  today is a clear evaluation error, not a broken host.
  [docs/native.md](docs/native.md) has the plan and the one command that
  vendors upstream to work against.
- Access reconciliation behind an explicit flag.
- A NixOS VM test covering bootstrap → sync → prune end to end.

## Prior art

[`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake)
packages the Infisical backend and frontend with `buildNpmPackage` and exposes
a `services.infisical` module plus cluster/backup/monitoring modules. It has no
bootstrap or secret-sync layer — which is most of what this repo is — but it is
well ahead on the packaging question and is worth reading before attempting the
native backend here.

## License

MIT — see [LICENSE](LICENSE).
