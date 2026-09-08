# nixfisical/nix/lib — the declaration + manifest layer.
#
# Two halves:
#
#   mkInfisical   attached to a `sops.secrets.<key>` entry, marks that secret
#                 developer-facing and says where in Infisical it lands.
#   manifestOf    walks a fleet's `nixosConfigurations` and collects every
#                 such annotation into a flat, deduped manifest.
#
# The manifest is STRUCTURE ONLY — it names SOPS keys, never values. Nothing
# decrypted ever enters the Nix store. The `nixfisical sync` CLI takes this
# manifest plus your age key and does the decryption at run time, on the
# operator's machine.
{ lib }:

rec {
  # Attach to a secret to export it. `project` is the hard access boundary in
  # Infisical, so it is the one field with no default — choosing it is a
  # security decision and should be explicit at every call site.
  #
  #   sops.secrets."services/bitcoin/rpc_password" = {
  #     infisical = nixfisical.lib.mkInfisical {
  #       project = "bitcoin-nodes";
  #       folder  = "/mainnet";
  #       groups  = [ "developers" ];
  #     };
  #   };
  mkInfisical =
    { project
    , folder ? "/"
    , environment ? "prod"
    , name ? null
    , groups ? [ ]
    }: {
      inherit project folder environment name groups;
    };

  # nixosConfigurations -> [ manifestEntry ]
  #
  # An entry carries its OWN `sopsFile`. sops-nix already tracks this per
  # secret (`sops.secrets.<k>.sopsFile`, defaulting to `sops.defaultSopsFile`),
  # so a fleet whose secrets are split across several encrypted files exports
  # correctly without the sync tool having to guess. Emitting it here is what
  # lets the CLI stay file-agnostic.
  manifestOf = nixosConfigurations:
    let
      perHost = lib.mapAttrsToList
        (host: node:
          lib.mapAttrsToList
            (key: sec:
              let e = sec.infisical or null; in
              if e == null then null else {
                sopsKey = key;
                sopsFile =
                  if (sec.sopsFile or null) != null
                  then toString sec.sopsFile
                  else null;
                inherit host;
                inherit (e) project environment folder groups;
                # Default the Infisical-side name to the last segment of the
                # SOPS key: "services/bitcoin/rpc_password" -> "rpc_password".
                name = if e.name != null then e.name else lib.last (lib.splitString "/" key);
              })
            (node.config.sops.secrets or { }))
        nixosConfigurations;

      flat = lib.filter (x: x != null) (lib.flatten perHost);

      # Dedupe on (sopsFile, sopsKey), not sopsKey alone: the same key path can
      # legitimately exist in two different encrypted files (e.g. a per-network
      # split), and collapsing those would silently drop one of them. Hosts
      # that share an entry are unioned into `hosts`.
      identity = e: "${toString e.sopsFile}#${e.sopsKey}";

      byKey = lib.foldl'
        (acc: e:
          let
            k = identity e;
            prev = acc.${k} or null;
          in
          acc // {
            ${k} =
              if prev == null
              then (removeAttrs e [ "host" ]) // { hosts = [ e.host ]; }
              else prev // { hosts = lib.unique (prev.hosts ++ [ e.host ]); };
          })
        { }
        flat;
    in
    lib.sort (a: b: identity a < identity b) (lib.attrValues byKey);

  # Fail the evaluation on manifest problems that would only surface as a
  # confusing HTTP 4xx halfway through a sync. Cheap to run at `nix flake
  # check` time; `nixfisical validate` repeats these against the rendered
  # JSON for anyone consuming the manifest outside Nix.
  assertManifest = manifest:
    let
      missingFile = lib.filter (e: e.sopsFile == null) manifest;
      badEnv = lib.filter
        (e: builtins.match "[a-z0-9-]+" e.environment == null)
        manifest;
      badFolder = lib.filter (e: !(lib.hasPrefix "/" e.folder)) manifest;

      err = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " (e: e.sopsKey) entries}";

      problems =
        (err "secrets with no sopsFile (set sops.defaultSopsFile or a per-secret sopsFile)" missingFile)
        ++ (err "environment slugs must match [a-z0-9-]+" badEnv)
        ++ (err "folder paths must be absolute (start with /)" badFolder);
    in
    if problems == [ ]
    then manifest
    else throw "nixfisical: invalid Infisical manifest:\n  - ${lib.concatStringsSep "\n  - " problems}";
}
