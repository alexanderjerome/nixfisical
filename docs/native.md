# The native server backend

`services.infisical.backend = "native"` is the goal: Infisical as a plain
systemd unit, built by Nix, with no container runtime on the host. Today it is
an evaluation error and `oci` is the only working backend. This note records
what the work involves so it can be picked up without re-deriving it.

## Why bother

The `oci` backend works, but it inherits everything a container image drags in:
the image tag is a mutable pointer that moves under you, the contents are not
reproducible from the flake, a container runtime has to exist on every host
that runs Infisical, and rollback means hoping the old tag still resolves.
None of that is how the rest of a NixOS fleet behaves.

There is a sharper reason too. Infisical runs Knex migrations against its
Postgres database on start. With a moving `latest-postgres` tag, a routine
host reboot can migrate the schema. A pinned, Nix-built server makes that a
deliberate act with a diff attached.

## What upstream actually is

Infisical's server is a Node/TypeScript application in the `backend/`
directory of [`Infisical/infisical`](https://github.com/Infisical/infisical),
released under tags shaped `infisical-core/v<version>`. A separate
React/Next.js frontend lives in `frontend/`. Migrations are Knex, invoked as
`npx knex migrate:latest --knexfile ./dist/db/knexfile.mjs` after the build.

To work on the packaging you want the actual source tree in front of you.
Vendor it as a **shallow submodule, for engineering reference only** — nothing
in the flake builds from it, and nothing ever should: a real package must
`fetchFromGitHub` at a pinned rev so consumers never need the submodule.

```sh
# populate (not committed yet — run this when you start the packaging work)
git submodule add --depth 1 \
  https://github.com/Infisical/infisical.git vendor/infisical
git config -f .gitmodules submodule.vendor/infisical.shallow true
git -C vendor/infisical fetch --depth 1 origin tag infisical-core/v0.97.4
git -C vendor/infisical checkout infisical-core/v0.97.4

# drop it once the package lands — it is scaffolding, not a dependency
git rm vendor/infisical
```

`.gitignore` does not exclude `vendor/`, so the submodule registers normally
when you add it. Keep it out of `nix/` so it is obvious it is not built.

## The shape of the work

1. **Package the backend.** `buildNpmPackage` with an `npmDepsHash`, sources
   pinned to `infisical-core/v<version>`, `sourceRoot` at `backend/`. Native
   build inputs include python3, gcc/make, and FreeTDS for the ODBC driver
   support in Infisical's dependency tree.
2. **Split the migration out.** Expose `infisical-migrate` as its own
   executable rather than folding it into the service's `ExecStartPre`, so a
   schema change is something an operator runs, not something a reboot does.
   The module can then offer `database.autoMigrate` defaulting to **false** —
   the opposite of the usual default, for the reason above.
3. **Frontend.** Same treatment, separate `npmDepsHash`. It can land later;
   the API is useful without it and the CLI in this repo never touches it.
4. **The unit.** systemd hardening (`NoNewPrivileges`, `ProtectSystem=strict`,
   `ProtectHome`, `PrivateTmp`, a `StateDirectory`, `LimitNOFILE=65536`), a
   dedicated user/group, and `EnvironmentFile=` pointed at the same
   `environmentFiles` option the `oci` backend already uses — the option
   surface should not change when the backend does.
5. **A hash-bump script**, because `npmDepsHash` cannot be computed lazily:
   `nix-prefetch-github Infisical infisical --rev infisical-core/v<version>`,
   then `npm ci` in a checkout to compute the deps hash.

## Read this first

[`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake)
(MIT) has already done steps 1, 3 and 4 — `infisical-backend`,
`infisical-frontend`, a `services.infisical` module with systemd hardening, and
an `update-hashes.sh`. It is early (a handful of commits, pinned to
`infisical-core/v0.97.4`) and has no bootstrap or sync layer, but it is a much
better starting point than a blank file. Depending on how it holds up, the
right answer here may be to consume it as a flake input for the package and
keep this repo focused on the bootstrap/reconcile layer that it lacks —
rather than maintaining a second copy of the same `buildNpmPackage`.

That decision should be made before writing any packaging code.
