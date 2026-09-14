# AGENTS.md — nixfisical

Declarative Infisical for NixOS fleets. SOPS stays the source of truth;
Infisical is the developer-facing view of it.

This file is the entry point when nixfisical is consumed as a flake input and
you have no checkout of it. There are three surfaces, and which one to reach
for depends on whether your question needs a running instance.

## 1. What can be declared — a file, not a server

```sh
nix build github:jeirslab/nixfisical#docs
```

Produces `index.md`, `options.json`, `options.md`, `commands.json`,
`commands.md`. Every option the NixOS and home-manager modules declare, and the
CLI's whole command tree, generated from the module system and the click tree
rather than written beside them — so an option added without a description is a
hole visible there, and a renamed one moves in the same commit.

No credentials, no network, no instance. If a question can be answered by a
file, it is answered here; nothing below re-serves this.

`nixfisical docs --format json` prints the command half alone, if the CLI is
already on PATH and you do not want a build.

## 2. What is true right now — the MCP server

```sh
nix run github:jeirslab/nixfisical#mcp -- --url https://infisical.example
```

Speaks MCP on stdio. Answers only what needs a live instance: `instance_status`,
`license`, `list_projects`, `list_secret_names`, `validate_manifest`,
`sync_diff`, `access_diff`, `keyring_audit`.

Two properties worth knowing before you wire it up:

- **It never returns a secret value.** Names, coordinates, versions, counts,
  drift — never material. Enforced in one place, as a whitelist.
- **It is read-only.** `--allow-writes` adds exactly one tool, `sync_apply`,
  which additionally refuses unless you pass the deletion count `sync_diff`
  reported for the same manifest. `sync` prunes; that number is the agreement.

MCP config in a consumer, at the launch directory's `.mcp.json`:

```json
{
  "mcpServers": {
    "nixfisical": {
      "command": "nix",
      "args": [
        "run", "github:jeirslab/nixfisical#mcp", "--",
        "--url", "https://infisical.example",
        "--admin-file", "secrets/infisical-admin.yaml"
      ]
    }
  }
}
```

It needs `sops` to reach the admin file, which the wrapped binary provides, and
an age key it can decrypt with — the same one the CLI uses.

## 3. How to operate it without breaking something

The `operate` skill (`.claude/skills/operate/`), loaded path-qualified when
this repo sits inside a workspace. It carries what neither of the above can:
the ordering, and the blast radii.

The five it exists for, in short — the skill has the detail:

1. **`sync` prunes.** Deleting an annotation deletes the secret. `--dry-run`
   first, always; it names every deletion.
2. **`sync` before `sync-access`.** `sync-access` grants against a project that
   `sync` creates. Reversed, the first convergence grants nothing and reports
   no error.
3. **`source` decides direction**, and a misspelled key reads as SOPS-owned —
   which overwrites a value this fleet did not author.
4. **The keyring project must not appear in the manifest.** `sync-access` would
   grant the estate's master key to a whole group.
5. **Group creation is licence-gated.** `nixfisical license` says so before a
   deploy finds out from a 400.

## Repo layout

| | |
| --- | --- |
| `pkgs/nixfisical/` | the Python CLI, agent, and MCP server |
| `nix/modules/` | the NixOS and home-manager modules |
| `nix/pkgs/` | their Nix packaging |
| `nix/docs/` | the generated reference in (1) |
| `examples/` | manifests and module usage |
| `README.md` | the long-form design document |

Rules for changing this repo: match the comment density you find — this
codebase explains *why*, and a patch that only says *what* reads as unfinished.
Every module docstring in `pkgs/nixfisical/nixfisical/` is load-bearing
documentation; `keyring.py` and `mcp.py` in particular state constraints that
the code below them depends on.

Tests are offline by construction: no server, no network. `nix flake check`
runs them plus the module evaluations and the docs build. A change that needs a
live instance to verify is an operation, not a check.
