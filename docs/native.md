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
directory of [`Infisical/infisical`](https://github.com/Infisical/infisical).
A separate React/Next.js frontend lives in `frontend/`. Migrations are Knex,
invoked as `npx knex migrate:latest --knexfile ./dist/db/knexfile.mjs` after
the build.

Releases are tagged `v<version>` — `v0.165.8` at the time of writing
(2026-09-09). The older `infisical-core/v<version>` scheme is **gone**: the
repo has no `refs/tags/infisical-core/*` left, so any command written against
it fails rather than resolving to something stale.

To work on the packaging you want the actual source tree in front of you.
Vendor it as a **shallow submodule, for engineering reference only** — nothing
in the flake builds from it, and nothing ever should: a real package must
`fetchFromGitHub` at a pinned rev so consumers never need the submodule.

```sh
# populate (not committed yet — run this when you start the packaging work)
git submodule add --depth 1 \
  https://github.com/Infisical/infisical.git vendor/infisical
git config -f .gitmodules submodule.vendor/infisical.shallow true
git -C vendor/infisical fetch --depth 1 origin tag v0.165.8
git -C vendor/infisical checkout v0.165.8

# drop it once the package lands — it is scaffolding, not a dependency
git rm vendor/infisical
```

`.gitignore` does not exclude `vendor/`, so the submodule registers normally
when you add it. Keep it out of `nix/` so it is obvious it is not built.

## The shape of the work

1. **Package the backend.** `buildNpmPackage` with an `npmDepsHash`, sources
   pinned to `v<version>`, `sourceRoot` at `backend/`. Native
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
   `nix-prefetch-github Infisical infisical --rev v<version>`, then `npm ci` in
   a checkout to compute the deps hash.

Note that steps 1–5 are all that `native` needs. The *option surface* is
already done and is deliberately backend-agnostic: `database.*`, `redis.*`,
`smtp.*`, `environmentFiles` and the rest describe the server's configuration
rather than its packaging, so they carry over unchanged. `native` has to
produce a unit that consumes them, not a second set of options.

## Prior art: read it, do not depend on it

[`connerohnesorge/infisical-flake`](https://github.com/connerohnesorge/infisical-flake)
(MIT) has already done steps 1, 3 and 4 — a `backend` and `frontend` package, a
`services.infisical` module with systemd hardening, and an `update-hashes.sh`.
It is a much better starting point than a blank file, and worth reading closely
before writing any packaging code.

**The consume-vs-package question is settled: package it here.** Checked
2026-09-09:

- Last modified 2025-10-08 — eleven months stale — with nixpkgs pinned to
  2025-08-06.
- It no longer evaluates. `nix eval
  github:connerohnesorge/infisical-flake#packages.x86_64-linux.backend.version`
  fails with `lib.customisation.callPackageWith: Function called without
  required argument "knex-cli"`. So it is not merely behind; it is broken
  against current nixpkgs.
- It is pinned to the retired `infisical-core/*` tag scheme, roughly 68 minor
  versions behind `v0.165.8`.
- It claims the same `services.infisical` option path this module does, so it
  could not be imported alongside this repo's module anyway.

Taking it as a flake input would mean inheriting a dead dependency on the
critical path of every consumer. Lift the approach — the `buildNpmPackage`
shape, the FreeTDS/python3 build inputs, the hardening — and keep the
maintenance here.
