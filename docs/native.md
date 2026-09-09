# The native server backend

`services.infisical.backend = "native"` runs Infisical as a plain systemd unit,
built by Nix from upstream source, with no container runtime on the host. It is
implemented; this note records why it is shaped the way it is, since most of
that is not obvious from the code and was expensive to find out.

`oci` remains the default and remains supported. The option surface is
identical between the two — `database.*`, `redis.*`, `smtp.*`,
`environmentFiles` and the rest describe the server's configuration rather than
its packaging, so switching backends is a one-line change.

## Why bother

The `oci` backend inherits everything a container image drags in: the tag is a
mutable pointer that moves under you, the contents are not reproducible from
the flake, a container runtime has to exist on every host, and rollback means
hoping the old tag still resolves.

There is a sharper reason. Infisical runs Knex migrations against its Postgres
database on start, so with a moving tag a routine reboot can migrate a
production schema. The native backend splits that apart:

| Unit                        | Does                                  |
| --------------------------- | ------------------------------------- |
| `infisical.service`         | runs the API. Never migrates.         |
| `infisical-migrate.service` | runs migrations. Nothing else does.   |

`database.autoMigrate` defaults to **false**, which is the opposite of the
usual NixOS default and deliberate: Infisical's migrations are not uniformly
reversible. `20260107083948_remove-old-memberships` drops six tables and
defines `down()` as a no-op. A migration you cannot undo is not something to
discover after a reboot has already applied it.

So an upgrade is:

```sh
infisical-migrate status          # what is pending
# ... back up the database ...
systemctl start infisical-migrate
systemctl restart infisical
```

The migration unit exists whether or not `autoMigrate` is set. That is the
point: there is one command, named the same on every host, rather than an
operator reconstructing a knex invocation against a store path under pressure.

## `migration:latest` is three steps, not one

This is the part worth writing down. Upstream's `npm run migration:latest`
expands to:

```
node ./dist/db/rename-migrations-to-mjs.mjs
  && knex --knexfile ./dist/db/auditlog-knexfile.mjs --client pg migrate:latest
  && knex --knexfile ./dist/db/knexfile.mjs        --client pg migrate:latest
```

Each step is load-bearing:

1. **`rename-migrations-to-mjs`** rewrites the `infisical_migrations` table,
   replacing `.ts` with `.mjs` in the recorded names. The built migrations are
   `.mjs`; an existing install recorded them under the `.ts` names they were
   applied with. Skip this and every migration looks pending. It mutates the
   *database*, not the store, and is gated on `NODE_ENV=production` — under any
   other value it silently returns without doing anything.
2. **The audit-log knexfile** is a *second, separate migration set*. Running
   only step 3 leaves the audit schema behind and appears to succeed. The
   knexfile `process.exit(0)`s cleanly when no dedicated audit database is
   configured, so the chain is safe under `set -euo pipefail`.
3. **The main knexfile.** Selects its config block by `NODE_ENV`, so that has
   to be `production` here too.

`infisical-migrate` reproduces this and adds `status` and `unlock`. It has no
`rollback` subcommand, for the `down()` reason above — offering one would
promise an undo that silently does not happen.

## Packaging notes

`nix/pkgs/infisical-backend.nix`, `buildNpmPackage` over `backend/` at a pinned
`v<version>` tag. Three things about it are non-obvious:

- **`npmDepsFetcherVersion = 2` is required, not a preference.** Infisical's
  `package.json` has nested `overrides` pinning *ranges* rather than exact
  versions (`eslint-plugin-import` → `minimatch: ^3.1.2`, and similar). npm
  re-resolves those against the registry during `npm ci` even though the
  lockfile already has an answer, and a sandboxed build dies on `ENOTCACHED`.
  `--legacy-peer-deps` alone does not fix it. Fetcher v2 caches registry
  *metadata*, not just tarballs, which does.
- **Four lockfile entries have to be filtered out.** `prefetch-npm-deps`
  fetches every entry in the lockfile; `npm ci` fetches only those matching the
  host's os/cpu. Infisical pins `@infisical/quic-darwin-arm64`, `-darwin-x64`,
  `-darwin-universal` and `-win32-x64` at versions that were never published —
  the registry answers 404 for all four, while both linux builds exist. A jq
  filter drops every `optional` entry that excludes linux. It must be applied
  to *both* the prefetch lockfile and the one in the unpacked source, because
  `npmConfigHook` refuses to build when they differ; hence one filter defined
  once in a `let` binding.
- **`dist/` is not self-contained.** `tsup` is configured with
  `skipNodeModulesBundle`, so the runtime needs `node_modules` beside it. The
  install prunes to production deps and copies both.

Oracle Instant Client is deliberately not vendored: upstream's image downloads
it from `download.oracle.com` under a licence forbidding redistribution, so it
cannot go in a public binary cache. Only the Oracle dynamic-secret provider
needs it.

## Bumping

```sh
nix run .#bump-infisical -- 0.166.0
```

Rewrites `version`, `srcHash` and `npmDepsHash` in
`nix/pkgs/infisical-backend.nix`. It resolves each hash by building that
attribute alone with a placeholder and reading the mismatch, source first —
`npmDeps` derives from the fetched source, so a wrong `srcHash` would make the
npm build fail on the source and report the wrong hash.

It does not build, test or commit. Read upstream's release notes for new
migrations before deploying.

## Release tags

Releases are tagged `v<version>` — `v0.165.8` at the time of writing. The older
`infisical-core/v<version>` scheme is **gone**: the repo has no
`refs/tags/infisical-core/*` left, so anything written against it fails rather
than resolving to something stale.

## Prior art

[`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake)
(MIT) packages a `backend` and `frontend` and a `services.infisical` module. It
was worth reading and is not worth depending on — checked 2026-09-09:

- Last modified 2025-10-08, with nixpkgs pinned to 2025-08-06.
- It no longer evaluates: `nix eval
  github:connerohnesorge/infisical-flake#packages.x86_64-linux.backend.version`
  fails with `callPackageWith: Function called without required argument
  "knex-cli"`. Not merely behind — broken against current nixpkgs.
- Pinned to the retired `infisical-core/*` tag scheme, roughly 68 minor
  versions behind.
- Claims the same `services.infisical` option path this module does, so it
  could not be imported alongside it anyway.

## Still missing

- **The frontend.** Same `buildNpmPackage` treatment, its own deps hash. The
  API is useful without it and this repo's CLI never touches the web UI, so it
  has not been done.
- **A NixOS VM test.** The units are verified by evaluation only. Nothing here
  has yet been run against a live Postgres.
