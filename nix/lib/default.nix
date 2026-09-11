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
            (attr: sec:
              let
                e = sec.infisical or null;
                # The attribute name is NOT the lookup path. sops-nix resolves a
                # value with `sops.secrets.<attr>.key`, which merely *defaults*
                # to <attr>; declaring `key` is the normal way to give a secret
                # a descriptive name on the host while the encrypted file stays
                # flat. Reading <attr> here produced a manifest that rendered,
                # validated and then failed mid-sync against a real instance
                # with "sops key 'cli-proxy/api_key' not found (no 'cli-proxy'
                # under <root>)" -- the file's key was `api_key`.
                sopsKey = sec.key or attr;
              in
              if e == null then null else {
                inherit sopsKey;
                sopsFile =
                  if (sec.sopsFile or null) != null
                  then toString sec.sopsFile
                  else null;
                inherit host;
                inherit (e) project environment folder groups;
                # Default the Infisical-side name to the last segment of the
                # SOPS key: "services/bitcoin/rpc_password" -> "rpc_password".
                name = if e.name != null then e.name else lib.last (lib.splitString "/" sopsKey);
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

      # `sops.secrets.<n>.key = ""` is sops-nix for "the whole file", which has
      # no single value to mirror. Caught here because an empty sopsKey reaches
      # the CLI as a lookup that cannot be phrased, let alone explained.
      emptyKey = lib.filter (e: e.sopsKey == "") manifest;

      err = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " (e: e.sopsKey) entries}";

      # Same, for problems where the sopsKey is itself the thing that is wrong
      # and so cannot name the offender.
      errBy = msg: entries:
        lib.optional (entries != [ ])
          "${msg}: ${lib.concatMapStringsSep ", " (e: "${e.project}${e.folder}:${e.name}") entries}";

      problems =
        (err "secrets with no sopsFile (set sops.defaultSopsFile or a per-secret sopsFile)" missingFile)
        ++ (err "environment slugs must match [a-z0-9-]+" badEnv)
        ++ (err "folder paths must be absolute (start with /)" badFolder)
        ++ (errBy "whole-file secrets (key = \"\") cannot be exported; name a key" emptyKey);
    in
    if problems == [ ]
    then manifest
    else throw "nixfisical: invalid Infisical manifest:\n  - ${lib.concatStringsSep "\n  - " problems}";
}
