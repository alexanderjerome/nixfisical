---
name: operate
description: Operate a self-hosted Infisical instance through nixfisical — converge a manifest, grant access, manage the keyring, provision a host for direct injection, or diagnose an instance that is not behaving. Use when a task involves the nixfisical CLI, its NixOS/home-manager modules, or an Infisical instance this flake manages.
---

# Operating an Infisical instance with nixfisical

Read this before running anything that writes. It carries the ordering and the
blast radii — the things that are wrong *silently*. What the options and
commands **are** is not here, because it is generated and this file would drift
from it:

```sh
nix build github:jeirslab/nixfisical#docs   # options.{json,md}, commands.{json,md}
nixfisical docs --format markdown           # the CLI tree alone, no build
```

What is true of a running instance is also not here. That needs the instance:

```sh
nix run github:jeirslab/nixfisical#mcp -- --url https://infisical.example
```

The MCP server is read-only unless started with `--allow-writes`, and it never
returns a secret value. It is the right way to answer "what would this change".

## The five that are silent

**1. `sync` prunes.** A secret in Infisical that the manifest no longer
declares is *deleted* on the next `sync`. Deleting a `mkInfisical` annotation is
therefore a delete, not a stop-exporting. `--dry-run` names every deletion; so
does the `sync_diff` tool, under `deletions`. Read that list before applying.
`--no-prune` exists for when you want the annotation gone and the value kept.

**2. `sync` before `sync-access`.** `sync-access` grants a group read access
*to a project*, so the project must already exist, and `sync` is what creates
it. Run in the other order, a first convergence grants nothing at all and
reports no error — it has nothing to grant against. Every convergence is:

```sh
nixfisical validate manifest.json          # structure, offline
nixfisical sync --dry-run manifest.json    # what would change, incl. deletions
nixfisical sync manifest.json              # then, and only then:
nixfisical sync-access manifest.json
```

**3. `source` decides direction, and a typo reads as "sops".** `source =
"sops"` means SOPS owns the value and `sync` pushes it up, overwriting what is
in Infisical. `source = "infisical"` means the instance owns it: `sync` creates
the coordinate but pushes no value, and `nixfisical import` pulls the value down
into the SOPS file. Misspell the field and the entry is SOPS-owned by default —
which overwrites a value this fleet did not author, with whatever placeholder is
in the store. `nixfisical validate` catches a bad *value* in that field; it
cannot catch a misspelled *key*.

**4. The keyring project must never appear in the manifest.** It holds the age
and SSH private keys the whole estate is encrypted to. `sync-access` puts the
manifest's groups on every project the manifest names — so listing the keyring
there hands the estate's master key to everyone in one of those groups, without
anyone deciding to. `nixfisical keyring audit` is what notices; run it after any
access change.

**5. Group creation is licence-gated.** On an unlicensed instance — the normal
case — `sync-access` cannot create a group, and finds out from a 400 partway
through. `nixfisical license` (or the `license` tool) says so first.
`--create-missing-groups` is the escape hatch and it writes to Infisical's
Postgres *behind the API*: it needs `psql`, which is deliberately not wrapped,
and it is not a thing to reach for on someone's behalf.

## Three ways a secret reaches a filesystem

They are for different machines. Picking the wrong one is the design mistake
this section exists to prevent.

| | Machine | What it does |
| --- | --- | --- |
| `nixosModules.export` | operator's | Annotates a `sops.secrets` entry so `sync` mirrors it into Infisical. Declaration only; nothing is fetched. |
| `nixosModules.inject` | a server | The host fetches its own secrets from the instance at boot, instead of through sops-nix. Experimental. A different trust model, not a better one: the instance becomes a boot-time dependency. |
| `homeManagerModules.agent` | a developer's laptop | A login session polls the instance and re-renders templates when a secret changes. |

Only the last polls, and that is deliberate. On a server, a secret changing
under a running process should be a restart an operator ordered.

## Bootstrap vs adopt

`bootstrap` initialises a fresh instance: superadmin, organization, the
`fleet-sync` machine identity, all recorded in the SOPS-encrypted admin file. It
fails on an instance that is already initialised. `adopt` is for that case — it
takes over an existing instance and writes the same admin file.

`nixfisical status` says which you need.

## Before you touch a fleet's instance

- **The admin file is per-organization.** One instance can carry several orgs
  (`add-org`), each with its own admin file. Never point a command at one org's
  file and another's manifest: the two are not interchangeable and the failure
  is a half-converged project in the wrong place. A per-org file has no `admin`
  block by design — that is not a corrupt file.
- **A dry run still decrypts.** `sync --dry-run` reads every SOPS value it
  would push and discards it. That is on purpose: a renamed or rotated age key
  is the thing you want to find out about in the dry run. It does mean a dry run
  needs a working key, and a `SopsError` there is about your key, not about the
  manifest.
- **Access is never revoked.** `sync-access` only adds. Removing a group from
  the manifest does not remove its access; that is a deliberate, manual act.
- **`provision-host` mints credentials.** It gives a host its own machine
  identity for direct injection. Run once per host; running it again is a new
  identity, not an idempotent no-op.

## When something is already wrong

Ask the instance before changing anything. In order:

1. `nixfisical status` — reachable, initialised, can `fleet-sync` log in. An
   *uninitialised* instance is a legitimate state, not a fault.
2. `nixfisical license` — before blaming the code for a 400 on a group.
3. `nixfisical sync --dry-run` — what the instance and the manifest actually
   disagree about.
4. `nixfisical keyring audit` — if the question is who can read what.

The MCP server answers all four without a checkout (`instance_status`,
`license`, `sync_diff`, `keyring_audit`), which is the faster path when the
instance is remote.

## What not to do on someone's behalf

- Apply a `sync` whose dry run showed deletions the user has not seen.
- Run `--create-missing-groups`, which writes behind the API.
- Print a secret value. `secrets get` exists for an operator at a terminal; a
  value in a transcript is a value that has leaked. Compare by hash.
- Point a command at a production instance to "check" something. The read-only
  MCP tools and `--dry-run` are that check.
