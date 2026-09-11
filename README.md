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
server backend builds and evaluates but has not yet been run against a live
Postgres — see [docs/native.md](docs/native.md).

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
#    (Instance already initialised? Use `adopt` instead — see "Adopting an
#    instance you did not bootstrap". `nixfisical status` will tell you which.)
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
| `packages.infisical-backend` | The Infisical API, built from source. No web UI. |
| `packages.infisical-frontend` | The Infisical web UI, as static files. |
| `packages.infisical-standalone` | Both, with the API serving the UI. |
| `overlays.default` | Puts all four in your package set. |

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
    enable   = true;
    siteUrl  = "https://infisical.example.com";
    imageTag = "v0.165.8";               # pin it; migrations run on start

    database = {
      host = "10.0.0.11";
      user = "infisical";
      name = "infisical";
    };
    redis.host = "10.0.0.10";

    smtp = {
      enable      = true;
      host        = "smtp.example.com";
      username    = "no-reply@example.com";
      fromAddress = "no-reply@example.com";
    };

    # Only the secrets live here now: see the table below.
    environmentFiles = [ config.sops.templates."infisical-env".path ];
  };

  sops.templates."infisical-env".content = ''
    ENCRYPTION_KEY=${config.sops.placeholder."services/infisical/encryption_key"}
    AUTH_SECRET=${config.sops.placeholder."services/infisical/auth_secret"}
    DB_PASSWORD=${config.sops.placeholder."dbs/infisical/password"}
    SMTP_PASSWORD=${config.sops.placeholder."services/infisical/smtp_password"}
  '';
}
```

Postgres and Valkey/Redis are yours to provide — the module does not manage
them, on purpose: in a fleet they usually live on separate hosts with their own
backup and blast-radius story. What the module does give you is the full
configuration surface for reaching them, so the only thing left in your sops
template is the credentials themselves.

### Which settings are options, and which are secrets

Infisical accepts the database connection either as one `DB_CONNECTION_URI` or
as discrete `DB_HOST`/`DB_PORT`/`DB_USER`/`DB_NAME`/`DB_PASSWORD` variables
(the URI wins when both are set, so the module refuses to evaluate if you
configure both). Discrete is the default here for one reason: a connection URI
embeds the password, so it can only ever come from an env file, while
host/port/user/name are not secret and belong in configuration you can read and
review.

| Secret — `environmentFiles` only | Option — safe in the store |
| -------------------------------- | -------------------------- |
| `ENCRYPTION_KEY`, `AUTH_SECRET`  | `siteUrl`, `host`, `port`  |
| `DB_PASSWORD`                    | `database.{host,port,user,name}` |
| `REDIS_PASSWORD`                 | `redis.{host,port,username}`, `database.rootCert` |
| `SMTP_PASSWORD`                  | `smtp.{host,port,username,fromAddress,…}` |
| `DB_READ_REPLICAS` (JSON of URIs)| `database.{poolMin,poolMax}` |

**Every option above defaults to null, and the module emits a variable only
when you set the matching option.** That is deliberate. For the `oci` backend
the options become `-e KEY=value` while `environmentFiles` becomes
`--env-file`, and Docker and Podman resolve `-e` *ahead of* `--env-file`. If
the module emitted defaults, an env file supplying the same key would be read
and silently ignored. Leaving an option null keeps the variable out of the
store entirely, so a fleet that treats (say) `SMTP_HOST` as sensitive can still
supply it from sops. The same rule applies to `extraEnvironment`.

Settings the module does not model as options — Redis Sentinel and Cluster
topologies, queue worker profiles, SSO — go through `extraEnvironment`.

### Do not use the `latest-postgres` tag

Infisical's older self-hosting docs recommend `infisical/infisical:latest-postgres`,
and it is a common default in hand-rolled deployments. It is a trap now. The
`-postgres` suffix dates from when Infisical also shipped a MongoDB variant;
upstream stopped publishing it. The tag still resolves, so nothing fails — but
it has not been rebuilt since **2025-08-08**, while `latest` rebuilt yesterday.
It is a silently frozen year-old image, not a moving pointer, and no
`-postgres` tag appears in the most recent 100 tags (checked 2026-09-09). If
you have a deployment on `latest-postgres`, it is a year behind and does not
look it. Pin `v0.165.8` or similar instead.

The module refuses to evaluate with an empty `environmentFiles` rather than
booting an instance with a default encryption key. Nothing secret is ever
written to the Nix store; `extraEnvironment` is for non-secret values only.

### The `native` backend

Every option above is backend-agnostic — they describe the server's
configuration, not how it is packaged — so swapping the container for a plain
systemd unit is one line plus the overlay:

```nix
{
  nixpkgs.overlays = [ nixfisical.overlays.default ];

  services.infisical = {
    backend = "native";                  # was "oci"
    # imageTag and virtualisation.oci-containers.backend become unused
    # ... everything else unchanged ...
  };
}
```

That builds Infisical from source at a rev pinned in this flake, and splits the
image's conflated entrypoint in two:

| Unit                        | Does                                |
| --------------------------- | ----------------------------------- |
| `infisical.service`         | runs the API. Never migrates.       |
| `infisical-migrate.service` | runs migrations. Nothing else does. |

`database.autoMigrate` defaults to **false**, the opposite of the usual NixOS
default. Infisical's migrations are not uniformly reversible — one of them
drops six tables and defines `down()` as a no-op — so an upgrade should be a
deliberate act, not something a reboot does:

```sh
infisical-migrate status          # what is pending
systemctl start infisical-migrate # after a backup
systemctl restart infisical
```

**The web UI is opt-in.** `package` defaults to `pkgs.infisical-backend`, which
is the API and nothing else — a browser pointed at it gets `{"statusCode":404}`,
not a login page. For the UI:

```nix
services.infisical.package = pkgs.infisical-standalone;
```

That is the same server with the frontend's static build placed where it looks
for it, and `STANDALONE_MODE` set by the package's own wrapper. There is no
module option, because the server crashes on start rather than 404s if the flag
is set on a build with no UI in it — choosing the package cannot be wrong that
way. `docs/native.md` has the details.

Bump the pinned release with `nix run .#bump-infisical -- 0.166.0`. It moves
the release and all three hashes together; the backend and the frontend must
come from the same tag.

[docs/native.md](docs/native.md) has the packaging details, including why
upstream's `migration:latest` is three steps rather than the one
`knex migrate:latest` you would expect.

**Option namespace.** This module claims `services.infisical`. If you also
import [`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake),
which claims the same path, the two will conflict — pick one.

## The CLI

```
nixfisical bootstrap     initialise a fresh instance, record creds in SOPS
nixfisical adopt         same, for an instance that is already initialised
nixfisical sync          converge the instance onto a manifest
nixfisical sync-access   grant manifest groups access to their projects
nixfisical validate      check a manifest offline (exit 2 on problems)
nixfisical status        is it reachable, and does the sync identity still work
nixfisical secrets       read, write and mint the SOPS values the rest reads
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

### Adopting an instance you did not bootstrap

`POST /api/v1/admin/bootstrap` succeeds exactly **once** in an instance's life.
An instance someone clicked through the setup wizard on, or one whose admin
file was lost with an old checkout, is therefore permanently out of
`bootstrap`'s reach — and short of dropping its database there was no way to
bring it under declarative management.

`adopt` is that way. It ends at the same admin file, reached from the other
side: instead of creating the superadmin and the organization it authenticates
as the superadmin that exists and finds the organization that exists, then runs
exactly the same tail — mint `fleet-sync`, write the file. Nothing downstream
can tell which command produced a given admin file.

```sh
nixfisical --url https://infisical.example.com adopt \
  --admin-email admin@example.com \
  --admin-password-from secrets/infisical.yaml:admin_password
```

`--organization` is optional when the account belongs to exactly one; with
more than one it is required, and the error lists them. Matching is by id,
then slug, then name.

Two differences from `bootstrap` that are not cosmetic:

- **The superadmin password is an input, not an output.** Bootstrap generates
  one that nobody ever types and the admin file is its only copy. Adopt has to
  be *given* the password of an account a human already logs in with, and
  records it alongside the machine credentials. Rotate it afterwards if that
  matters. There is no generate fallback — inventing a password for an account
  that exists would produce a confident "Invalid credentials".
- **It refuses to reuse an identity name.** If the organization already has a
  machine identity called `fleet-sync`, adopt stops. Infisical shows a client
  secret once, at creation, so an existing identity cannot be adopted into an
  admin file at all — there is nothing to read back. Delete it, or pass
  `--identity-name`.

MFA on the superadmin account stops adopt, by design. Upstream enforces it at
organization selection rather than at login, so the refusal happens after the
password has been accepted; completing a TOTP challenge belongs in an
interactive tool, not in something that may be running from a deploy script.

`status` reads "has this been initialised?" off the instance
(`GET /api/v1/admin/config`) rather than inferring it from whether an admin
file happens to exist locally. Those are independent facts, and the case where
they disagree — initialised instance, no admin file — is exactly the one
`adopt` exists for, so it is the one worth naming rather than mislabelling as
"not bootstrapped yet".

### Group access

`sync-access` reads the same manifest as `sync` and grants each `groups` entry
access to the projects it appears in. It is a separate command on purpose: it
needs different credentials, it fails for entirely unrelated reasons, and a
`sync` that refused to write secrets because a group was missing would be the
wrong coupling.

Access is granted at the **project** level. A group named on any entry of a
project gets the whole project, so `project` is the access boundary the
manifest actually expresses — `environment` and `folder` do not narrow it.
Access is never revoked; remove it in the UI.

Two mechanisms, and the split matters:

- **Adding an existing group to a project** is a supported, ungated API call.
  This runs by default and needs nothing but the sync identity.
- **Creating a group** is gated behind an enterprise plan. Upstream's
  `getDefaultOnPremFeatures()` sets `groups: false`, and the create endpoint
  answers `400 plan restriction`.

So `--create-missing-groups` writes to Infisical's Postgres directly. It is off
by default, prints a warning when set, and is the only operation in this tool
that touches the database. Point it at the database with `--db-host` and give
it a password via `--db-password-from FILE:KEY` (SOPS) or `$PGPASSWORD`.

The load-bearing asymmetry that makes this safe rather than merely expedient:
upstream gates group *mutation*, but not permission *evaluation*. A group
created this way is honoured by the permission service exactly like any other
— `permission-service.ts` contains no license check. This is not forging an
entitlement, it is writing the rows the UI would have written.

Because it is raw SQL against a schema with no compatibility promise, it
refuses to run on a schema it does not recognise rather than corrupting one.
A preflight checks every column it writes and aborts if any pre-`v0.165.8`
membership table is still present — the schema was consolidated into
`memberships`/`membership_roles` by migration
`20260107083948_remove-old-memberships`, whose `down()` is a no-op. The schema
it is verified against is recorded in `access.py` as
`SCHEMA_VERIFIED_AGAINST`.

Run it with `--dry-run` first; it reports every group it would create and
every grant it would make, and writes nothing.

### Minting and editing secrets

`secrets` is the local half of the tool. It talks to no instance — it operates
on exactly the SOPS files the manifest points at, which is why it lives here
rather than in a second binary. An estate that keeps its source of truth in
SOPS and projects it into Infisical should not need two tools to do it.

```
nixfisical secrets list                    every leaf key path in a store
nixfisical secrets get KEY                 one value, to stdout
nixfisical secrets set KEY [VALUE]         prompted and confirmed if VALUE is omitted
nixfisical secrets rm  KEY                 delete a key, pruning emptied parents
nixfisical secrets edit                    hand off to `sops` on the whole file
nixfisical secrets gen  KIND               mint fresh material
```

The store is named once with `-f/--file` or `$NIXFISICAL_SECRETS_FILE`, on the
group or on any subcommand.

`set` with no `VALUE` and no `--stdin` prompts hidden and confirms, because a
secret passed as an argument is a secret in the shell history and in every
`/proc/*/cmdline` on the box. `--stdin` reads the whole of stdin verbatim, so
multi-line material — a PEM, a private key — round-trips byte for byte.

**`gen` converges, it does not overwrite.** The reason it takes `--into` more
than once is that shared credentials are the common case: Authentik's Postgres
password belongs in the Authentik host's file *and* in the database host's,
an OAuth2 client secret in the provider's file *and* the consumer's. Minting
those by hand means generating once and pasting twice, and the failure mode is
not an error — it is two files that agree today and diverge at the next
rotation, surfacing months later as an authentication failure somewhere
unrelated.

```sh
nixfisical secrets gen alnum --length 48 \
    --into secrets/authentik.yaml:db_password \
    --into secrets/infra-db.yaml:authentik
```

So, given N destinations: if none hold a value it generates one and writes it
to all N; if some hold the same value it propagates that value to the rest and
generates nothing; if all agree it does nothing and exits 0; and if they
*disagree* it refuses, names them, and demands `--rotate` — because deciding
which copy is the stale one is not a call this tool should make silently.
Re-running is a no-op. Adding a fourth consumer later and re-running copies
the existing value into it rather than rotating the other three.

Kinds are named rather than spelled out in `openssl` flags, so the next person
reads `kind: alnum, length: 48` and knows what is in the store without
decrypting it: `alnum`, `hex`, `urlsafe`, `base64`, `password`, `uuid`.
`--length` always counts **output characters**, for every kind — unlike
`openssl rand`, which counts input bytes, and where `-base64 32` yields 44
characters rather than 32. Lengths below 12 are refused.

A service needs six or seven secrets at once, so `--plan` takes the whole set
at once. It is reviewable in a PR and, because generation converges, safe to
re-run at any time:

```yaml
# secrets/authentik.plan.yaml
file: secrets/authentik.yaml     # default store for the bare keys below
secrets:
  - kind: urlsafe
    length: 60
    note: AUTHENTIK_SECRET_KEY
    into: [secret_key]
  - kind: alnum
    length: 48
    note: shared with the database host, must stay byte-identical
    into:
      - db_password
      - secrets/infra-db.yaml:authentik
```

Paths in a plan resolve relative to the plan file's own directory, so a plan
travels with the repo it describes. `--dry-run` reports every write it would
make and performs none. `--print` writes the generated value to stdout for the
one case that needs it — pasting a bootstrap password into a UI once. It is
not for scripts; those should use `secrets get`, which reads the store rather
than racing it.

## What it does not do yet

**Folder pruning.** Secrets are pruned; empty folders are left behind.

## Roadmap

- Reporting group access that exists on the instance but is not in the
  manifest. `sync-access` never revokes, so drift in that direction is
  currently invisible.
- A NixOS VM test covering bootstrap → sync → prune end to end, and one
  covering the `native` units against a live Postgres — they are currently
  verified by evaluation only.

## Prior art

[`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake)
packages the Infisical backend and frontend with `buildNpmPackage` and exposes
a `services.infisical` module plus cluster/backup/monitoring modules. It has no
bootstrap or secret-sync layer — which is most of what this repo is — but it
had already answered the packaging question, and was worth reading closely
before the `native` backend here was written.

Read it, do not depend on it. Checked 2026-09-09: last modified 2025-10-08,
nixpkgs pinned to 2025-08-06, and it no longer evaluates —
`packages.x86_64-linux.backend` fails with `callPackageWith: Function called
without required argument "knex-cli"`. It also claims the same
`services.infisical` option path as this module, so importing both conflicts.

## License

MIT — see [LICENSE](LICENSE).
