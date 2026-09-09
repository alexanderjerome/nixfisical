# The Infisical API server, built from source rather than pulled as an image.
#
# This is the package behind `services.infisical.backend = "native"`. The point
# of it is pinning: the `oci` backend's image tag is a mutable pointer, and
# Infisical runs Knex migrations against its database on start, so with a
# moving tag a routine host reboot can migrate a production schema. Here the
# version is a rev in this file and a rebuild is a diff.
#
# Two executables come out, and the split is the whole reason this exists:
#
#   infisical-server    runs the API. Never migrates.
#   infisical-migrate   runs the migrations. Nothing else does.
#
# Upstream's container conflates them -- its `npm start` is preceded by
# migrations in the entrypoint -- which is exactly the behaviour worth losing.
#
# `infisical-migrate` reproduces upstream's `migration:latest` script, which is
# three steps and not the one `knex migrate:latest` you might assume:
#
#   1. rename-migrations-to-mjs.mjs   (the built migrations are .mjs, but knex
#                                      resolves them by the .ts names recorded
#                                      in the migrations table)
#   2. the *audit log* knexfile       (a second, separate migration set)
#   3. the main knexfile
#
# Running only step 3 leaves the audit-log schema behind and appears to work.
#
# It also takes `status` and `unlock`, because the module defaults to manual
# migrations and an operator about to run one wants to see the pending list
# first. There is no `rollback`; see the usage text for why.
{ lib
, fetchFromGitHub
, buildNpmPackage
, fetchNpmDeps
, runCommand
, jq
, nodejs_22
, python3
, makeWrapper
, unixodbc
, freetds
, openssl
, runtimeShell
, git
}:

let
  nodejs = nodejs_22;

  # These three are the whole of a version bump, which is why they sit together
  # at the top rather than next to what uses them. `nix run .#bump-infisical --
  # <version>` rewrites all three in place; it matches on these exact names, so
  # keep them one-per-line and literal.
  version = "0.165.8";
  srcHash = "sha256-VGaGbV77VuLckTMDf0Gl5Qa7uVmfN9XuJ5mdltRpVF8=";
  npmDepsHash = "sha256-1AOYW4SQ7y5/ERCYQiyDSpj2zpPS6VeBZFgzFsbigKg=";

  source = fetchFromGitHub {
    owner = "Infisical";
    repo = "infisical";
    rev = "v${version}";
    hash = srcHash;
  };

  # `prefetch-npm-deps` fetches every entry in the lockfile; `npm ci` fetches
  # only those matching the host's os/cpu. That difference is normally
  # invisible, but Infisical's lockfile pins `@infisical/quic-darwin-arm64`,
  # `-darwin-x64`, `-darwin-universal` and `-win32-x64` at versions that were
  # never published -- the registry answers 404 for all four, while the two
  # linux builds are present. So the prefetch fails on packages the build would
  # never have installed.
  #
  # Dropping every optional entry that excludes linux fixes it. This package is
  # linux-only, so on the platforms it targets the filter removes exactly what
  # npm would have skipped by itself.
  #
  # It has to be applied in two places: to the lockfile the prefetcher reads,
  # and to the one in the unpacked source, because `npmConfigHook` refuses to
  # build when the two differ. Hence one filter defined once -- if these drift
  # the build fails with a hash mismatch that says nothing about the cause.
  lockFilter = ''
    def foreignOptional:
      (.optional == true) and (has("os")) and ((.os | index("linux")) == null);
    .packages |= with_entries(select(.value | foreignOptional | not))
  '';

  npmLock = runCommand "infisical-backend-npm-lock"
    {
      nativeBuildInputs = [ jq ];
    } ''
    mkdir -p $out
    cp ${source}/backend/package.json $out/package.json
    jq ${lib.escapeShellArg lockFilter} \
      ${source}/backend/package-lock.json > $out/package-lock.json
  '';
in
buildNpmPackage {
  pname = "infisical-backend";
  inherit version;

  src = source;

  # Upstream is a monorepo; only `backend/` is packaged here. The frontend is
  # a separate build and the API is useful without it -- nothing in this repo's
  # CLI touches the web UI.
  sourceRoot = "${source.name}/backend";

  # Fetcher v2 caches registry *metadata*, not just tarballs. Infisical's
  # package.json carries nested `overrides` that pin ranges rather than exact
  # versions (`eslint-plugin-import` -> `minimatch: ^3.1.2`, and similar), and
  # npm resolves those ranges during `npm ci` even though the lockfile already
  # has an answer. With v1 that resolution hits the network and the sandboxed
  # build dies on ENOTCACHED.
  npmDepsFetcherVersion = 2;

  npmDeps = fetchNpmDeps {
    src = npmLock;
    fetcherVersion = 2;
    hash = npmDepsHash;
  };

  inherit nodejs;

  nativeBuildInputs = [
    python3 # node-gyp, for pkcs11js and the odbc bindings
    makeWrapper
    jq # postPatch, above
  ];

  buildInputs = [
    unixodbc # `odbc`, used by the SAP ASE dynamic-secret provider
    freetds # the TDS driver unixODBC loads for it
    openssl
  ];

  # `min-release-age=7` tells npm to refuse packages published in the last
  # week. That is a supply-chain measure aimed at `npm install` resolving new
  # versions; here every version is already fixed by the lockfile and the store
  # path, so it has nothing to decide and only needs the registry metadata it
  # cannot reach in a sandbox.
  postPatch = ''
    rm -f .npmrc
    jq ${lib.escapeShellArg lockFilter} package-lock.json > package-lock.json.filtered
    mv package-lock.json.filtered package-lock.json
  '';

  # Oracle Instant Client is not vendored. Upstream's image downloads it from
  # download.oracle.com under a licence that forbids redistribution, so it
  # cannot go in a public binary cache. Only the Oracle dynamic-secret provider
  # needs it; everything else works without it.

  # Without this npm tries to resolve a peer dependency (`minimatch`) against
  # the live registry mid-`npm ci`, which a sandboxed build cannot reach. The
  # lockfile already pins the whole tree; legacy resolution just stops npm
  # second-guessing it.
  npmFlags = [ "--legacy-peer-deps" ];

  buildPhase = ''
    runHook preBuild
    npm run build
    runHook postBuild
  '';

  # `tsup` is configured with `skipNodeModulesBundle`, so `dist/` is not
  # self-contained: the runtime needs `node_modules` beside it. Prune to
  # production deps first -- the dev tree carries the whole toolchain.
  installPhase = ''
    runHook preInstall

    npm prune --omit=dev --offline --no-audit --no-fund --legacy-peer-deps

    mkdir -p $out/lib/infisical
    cp -r dist node_modules package.json $out/lib/infisical/

    makeWrapper ${nodejs}/bin/node $out/bin/infisical-server \
      --add-flags "--enable-source-maps" \
      --add-flags "$out/lib/infisical/dist/main.mjs" \
      --set-default NODE_ENV production \
      --prefix PATH : ${lib.makeBinPath [ git ]}

    makeWrapper ${runtimeShell} $out/bin/infisical-migrate \
      --add-flags "$out/lib/infisical/migrate.sh" \
      --set-default NODE_ENV production \
      --set INFISICAL_LIB "$out/lib/infisical" \
      --set NODE "${nodejs}/bin/node"

    cat > $out/lib/infisical/migrate.sh <<'EOF'
    set -euo pipefail
    cd "$INFISICAL_LIB"

    KNEX="$INFISICAL_LIB/node_modules/.bin/knex"
    # Two migration sets against two knexfiles. The audit-log one goes first,
    # matching upstream's `migration:latest`; running only the main one leaves
    # the audit schema behind and says nothing about it.
    AUDIT=(--knexfile ./dist/db/auditlog-knexfile.mjs --client pg)
    MAIN=(--knexfile ./dist/db/knexfile.mjs --client pg)

    # The built migrations are .mjs but an existing `infisical_migrations`
    # table records the .ts names they were applied under. This rewrites the
    # table so knex recognises what it has already run -- without it every
    # migration looks pending. It touches the database, not the store, and is
    # a no-op once done, so it also has to precede a read-only `status`.
    rename() { "$NODE" ./dist/db/rename-migrations-to-mjs.mjs; }

    case "''${1:-latest}" in
      latest)
        rename
        "$KNEX" "''${AUDIT[@]}" migrate:latest
        "$KNEX" "''${MAIN[@]}" migrate:latest
        ;;
      status)
        rename
        "$KNEX" "''${AUDIT[@]}" migrate:status
        "$KNEX" "''${MAIN[@]}" migrate:status
        ;;
      unlock)
        "$KNEX" "''${AUDIT[@]}" migrate:unlock
        "$KNEX" "''${MAIN[@]}" migrate:unlock
        ;;
      *)
        echo "usage: infisical-migrate [latest|status|unlock]" >&2
        echo "" >&2
        echo "  latest  apply every pending migration (default)" >&2
        echo "  status  list applied and pending, changing nothing" >&2
        echo "  unlock  clear a migration lock left by a killed run" >&2
        echo "" >&2
        # Deliberately no rollback. Infisical's migrations are not uniformly
        # reversible -- 20260107083948_remove-old-memberships drops six tables
        # and defines down() as a no-op -- so a rollback subcommand here would
        # promise an undo that silently does not happen. Restore from backup.
        echo "There is no rollback: Infisical's down() migrations are not" >&2
        echo "uniformly implemented. Restore the database from a backup." >&2
        exit 1
        ;;
    esac
    EOF
    chmod +x $out/lib/infisical/migrate.sh

    runHook postInstall
  '';

  # `dist/main.mjs` boots the server, which wants a database. There is nothing
  # to check here beyond the build having produced its entrypoints.
  doCheck = false;

  postInstallCheck = ''
    test -f $out/lib/infisical/dist/main.mjs
    test -f $out/lib/infisical/dist/db/knexfile.mjs
    test -f $out/lib/infisical/dist/db/auditlog-knexfile.mjs
  '';

  meta = with lib; {
    description = "Infisical secrets-management API server";
    homepage = "https://github.com/Infisical/infisical";
    license = licenses.mit; # backend/ is MIT; ee/ is source-available
    platforms = platforms.linux;
    mainProgram = "infisical-server";
  };
}
