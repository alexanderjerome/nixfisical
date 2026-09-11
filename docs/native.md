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

## Three packages

| Package                | Is                                               |
| ---------------------- | ------------------------------------------------ |
| `infisical-backend`    | the API. No web UI: every path outside `/api` answers 404 in JSON. |
| `infisical-frontend`   | the web UI, as static files. Nothing serves it.  |
| `infisical-standalone` | both, arranged so the API serves the UI in-process. |

`services.infisical.package` defaults to `infisical-backend`, so a browser
pointed at a default native instance gets `{"statusCode":404}` rather than a
login page. Set the option to `pkgs.infisical-standalone` to get the UI. There
is no module option for it, and that is on purpose: the server locates the UI's
files at a path derived from where its *own code* is, and `readFileSync`s
`index.html` when the plugin registers rather than when a request arrives — so
a flag saying "serve the UI" on a package that does not carry one is not a 404,
it is a crashloop. Choosing the package cannot be wrong in that way.

### How the UI is served

There is no separate web server and no `next start`. Infisical's frontend
(upstream calls the workspace `frontend-v2`) is Vite + React and builds to a
static `dist/`; the API serves it itself when `STANDALONE_MODE` is set, via
`@fastify/static` plus a `GET /*` SPA fallback that excludes `/api`. That is
what upstream's own `Dockerfile.standalone-infisical` does.

The awkward part is *where*. `backend/src/server/app.ts` computes

```js
dir = path.join(__dirname, "../../")
```

from the directory of the running `dist/server/app.mjs`, and roots the static
handler at `<dir>/frontend-build`. No env var, no flag, no way to point it
elsewhere. So `infisical-standalone` has to put the UI inside the backend's own
directory layout. Node resolves symlinks before computing `__dirname`, which
rules out symlinking `dist/` — it would resolve back into `infisical-backend`'s
store path, which has no `frontend-build`. Hence: `dist/` is a real copy
(47 MB), `node_modules` stays a symlink (621 MB, and nothing in there computes
a directory from a file), `frontend-build` is a symlink to the frontend.

`STANDALONE_MODE=true` is set by the standalone package's own wrapper with
`--set-default`, so it travels with the build that can honour it and an
operator can still turn it off per-host without switching packages.

The split is not just tidiness. `infisical-backend` is an hour of npm and
native-addon linking; the UI is a Vite build and a directory of files. Folding
them into one derivation would mean paying that hour every time either moved.

## Packaging notes

`nix/pkgs/infisical-backend.nix`, `buildNpmPackage` over `backend/` at a pinned
`v<version>` tag; `infisical-frontend.nix` is the same over `frontend/`. The
release and its source hash live once in `infisical-source.nix`, because a
backend and a frontend from different releases is a mismatch nothing else would
catch — the API would answer and the UI would be subtly wrong.

Four things about the backend are non-obvious:

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
  once, in `infisical-source.nix`. The frontend reuses it — it has no
  unpublished entries, but it does carry 46 foreign esbuild/rollup/swc/oxide
  binaries that there is no reason to fetch.
- **`dist/` is not self-contained.** `tsup` is configured with
  `skipNodeModulesBundle`, so the runtime needs `node_modules` beside it. The
  install prunes to production deps and copies both.
- **The prune must not get `--legacy-peer-deps`, though the install must.**
  `npm ci` needs the flag to stop re-resolving the lockfile's ranges. `npm
  prune` decides what is *reachable* and deletes the rest, and under legacy
  resolution peer dependencies are reachable from nothing — it removed
  `express-session`, which nothing declares directly and `connect-redis` only
  asks for as a peer. The build succeeded and the server died on every start
  with `ERR_MODULE_NOT_FOUND`. A `postInstallCheck` now walks the pruned tree
  and asserts every required peer still resolves; it needs `doInstallCheck =
  true` to run at all, which is not the default.

The frontend has two of its own:

- **Dependencies install with `--ignore-scripts`**, as upstream's Dockerfile
  does. Every native thing in that tree — esbuild, rollup, `@swc/core`,
  tailwind's oxide — ships a prebuilt binary per platform, and its install
  script exists to *download* one when the prebuilt is missing. In a sandbox
  that is a fetch that cannot happen; with the lockfile's linux binaries
  present it is a fetch that does not need to.
- **`INFISICAL_PLATFORM_VERSION` must be set at build time.** `vite.config.ts`
  stamps it into every asset filename and falls back to the literal `0.0.1`,
  so without it the bundle claims to be a version that was never released.
  Both spellings are set, `VITE_`-prefixed and not, because the config reads
  one then the other and upstream sets both rather than picking.

Oracle Instant Client is deliberately not vendored: upstream's image downloads
it from `download.oracle.com` under a licence forbidding redistribution, so it
cannot go in a public binary cache. Only the Oracle dynamic-secret provider
needs it.

## Bumping

```sh
nix run .#bump-infisical -- 0.166.0
```

Rewrites four values across three files: `version` and `srcHash` in
`infisical-source.nix`, and a `npmDepsHash` in each of `infisical-backend.nix`
and `infisical-frontend.nix`. It resolves each hash by building that attribute
alone with a placeholder and reading the mismatch, source first — `npmDeps`
derives from the fetched source, so a wrong `srcHash` would make the npm build
fail on the source and report the wrong hash.

Both npm hashes move together. They come from lockfiles inside the same source
tarball, so leaving one behind is not a stale-but-working pin; it is a mismatch
against a tarball that no longer contains what the hash was taken from, and the
error says nothing about a bump being the reason.

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

- **A NixOS VM test.** The units are verified by evaluation only, and the
  standalone package's join — a real `dist/`, a symlinked `node_modules`, a
  symlinked `frontend-build` — is verified by `test -f` at build time and by
  one host in one fleet at run time. A VM test that boots the server against a
  live Postgres and asserts `GET /` returns HTML is the thing that would catch
  upstream moving `dir` out from under it.
- **`CDN_HOST` and the CSP rewriting.** `serve-ui.ts` will rewrite asset URLs
  and Content-Security-Policy directives when `CDN_HOST` is set. Nothing here
  exposes that; `extraEnvironment` reaches it if you need it.
