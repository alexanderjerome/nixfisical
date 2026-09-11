# Reference declarations

These files are a **scaffold**, not working code. They exist so the shape of
the configuration module can be argued about before it is built, and so that
the parts we do not need yet are written down rather than rediscovered.

Everything here was read off `docs/openapi.json` — the Infisical OpenAPI
document, 1479 paths, every schema inlined. Where a file states a field name,
a type, an enum or a default, it came from that document and not from the
prose documentation, which lags.

## The one rule: bare

Option names are **the platform's own wire names**. `secretPath`, not `path`.
`rotationInterval`, not `intervalDays`. `isAutoSyncEnabled`, not `autoSync`.
`destinationConfig`, not `config`.

This is uglier to write and it is the right trade. It buys three things:

- Every option is greppable against `openapi.json`. When something does not
  work, the question "what does the API actually call this" has one answer.
- The leaf option sets can be **generated** from the spec rather than hand
  written. There are 84 app-connection kinds, 49 sync destinations, 28
  rotation types and 27 dynamic-secret providers — 188 provider variants,
  each with its own inlined config schema. Hand-writing ten of those
  guarantees the eleventh is a rewrite.

  (Each of the first three path prefixes also carries an `/options` endpoint
  listing what is available. It is metadata, not a provider. Counting it is
  how you get the 85/50/29 that an earlier draft of this file claimed.)
- A renaming layer is a place for bugs to live that has no upside. The
  reconciler's job is to send this object to that API.

Exceptions, all forced by Nix rather than chosen:

- Lists keyed by a natural identifier become attribute sets. The API's
  `environments: [{slug: "prod", ...}]` is `environments.prod = { ... }`.
  The attribute name is the identifier the API uses for lookup.
- `projectId`, `connectionId`, `folderId` and friends are server-assigned
  UUIDs. They are never written by hand; the declaration refers to things by
  the name it gave them and the reconciler resolves.
- `$`-prefixed permission operators (`$eq`, `$glob`, `$in`) need quoting:
  `secretPath."$glob" = "/apps/**"`.

## Values

A secret entry declares **identity, metadata, and where the value comes
from**. It does not declare the value's storage.

```nix
KEY.sopsFile = ./secrets.yaml;              # sugar, see below
KEY.valueFrom = { resolver = "vault"; ... }; # the general form
KEY.value = "not actually a secret";         # literal — lands in the store
KEY.unmanaged = true;                        # exists, owned elsewhere
```

`valueFrom` names a resolver and carries an arbitrary payload. A resolver is
a program: descriptor as JSON on stdin, raw value bytes on stdout, non-zero
exit fails the entry. sops, vault, pass, 1Password, gpg, age and `echo` all
satisfy that contract identically, and the manifest that leaves Nix eval
therefore contains descriptors only, never plaintext — by construction rather
than by our care.

`sopsFile`/`sopsKey` is **sugar over that**, and sops-nix is a declared
dependency of this module because the sugar is worth it. It desugars to
`{ resolver = "sops"; file = ...; key = ...; }`. Removing sops-nix would cost
the sugar and nothing else.

`value` is a literal and lands in the Nix store world-readable. That is
correct for the large amount of non-secret configuration that lives in
Infisical — upstream URLs, ports, feature flags, `${...}` references — and
wrong for anything else. The name is deliberately not shared with `valueFrom`
so that the difference cannot be missed at a glance.

`unmanaged` declares that a key exists and that we do not own its value. It
is what keeps `prune` from deleting the output of a rotation, a replicating
import, or a sync's `import-secrets`.

## Files

| File | Scope | Built today |
| --- | --- | --- |
| `00-minimal.nix` | the smallest thing that does something | mostly |
| `10-instance.nix` | instance, resolvers, gateways, relays | no |
| `20-organization.nix` | org roles, groups, identities, templates, sub-orgs | partly |
| `30-project.nix` | project settings, environments, folders, tags, RBAC | partly |
| `40-secrets.nix` | static secrets, imports, references, pruning | mostly |
| `50-connections.nix` | app connections (84 kinds) | no |
| `60-syncs.nix` | secret syncs (49 destinations) | no |
| `70-rotations.nix` | secret rotations (28 types) | no |
| `80-dynamic-secrets.nix` | dynamic secrets (27 providers) + leases | no |
| `90-pki.nix` | cert-manager projects | no |
| `91-kms.nix` | KMS keys and signing | no |
| `92-kubernetes.nix` | every Kubernetes touchpoint | no |
| `93-federation.nix` | sub-orgs, SSO, SCIM, external-infisical | no |
| `99-jeirslab.nix` | what the lab actually runs | yes |

"Built today" means nixfisical's reconciler does something with it. Read
`99-jeirslab.nix` first if you want to know what is real — the honest total
is two secrets, and it records what the current annotation model cannot say
and why each gap matters.

The "no" rows are not a roadmap. They are a record of what the API offers so
that the decision not to build something is made once, with the surface in
view, instead of rediscovered.

## What is deliberately absent

**Approval policies.** Secret-approval and access-approval are EE routes and
do not appear in the public OpenAPI document at all — the only `approval`
path among 1479 is `/api/v1/cert-manager/signers/{signerId}/approval-policy`.
We cannot declare them. We can only not crash when one is active, which means
every mutating secret call must tolerate a `{approval}` response in place of
the `{secret}` it asked for.

The one exception is **certificate signing**, which has a real, declarable
approval policy at `PUT /api/v1/cert-manager/signers/{signerId}/approval-policy`
— multi-step, per-step quorum, rate-limited. See `90-pki.nix`.

**Anything read-only or ephemeral.** Audit log queries, lease inspection,
sync job status, scan findings. A declaration says what should be true, not
what is.

**Gateway pools.** `gatewayPoolId` is a foreign key on gateway auth, identity
auth, dynamic secrets, identity templates, HSM connectors and PKI discovery
jobs, and there is no endpoint anywhere in 1479 paths that creates a pool.
Treat a pool id as an opaque value from elsewhere.

**Relays.** `GET /api/v1/relays` is the entire surface. List only.

**OAuth clients.** `oauth-clients` exists as a permission subject with
read/create/edit/delete actions and there is no endpoint those actions
govern.

**SCIM tokens.** SCIM's only writable endpoint is group-to-role mappings. The
bearer token is minted in the UI, so bootstrapping SCIM is manual.

**Kubernetes as a destination.** There is no Kubernetes app-connection kind
and no Kubernetes sync destination. Infisical does not write Secret objects
through this API; that is the Operator, which reads. See `92-kubernetes.nix`.
