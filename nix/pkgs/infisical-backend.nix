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
, buildNpmPackage
, fetchNpmDeps
, jq
, nodejs_22
, python3
, makeWrapper
, unixodbc
, freetds
, openssl
, runtimeShell
, git
, infisicalSource
}:

let
  nodejs = nodejs_22;

  inherit (infisicalSource) version src;

  # Half of a version bump; the other half -- the release and its source hash
  # -- is in infisical-source.nix, shared with the frontend. `nix run
  # .#bump-infisical -- <version>` rewrites this in place; it matches on this
  # exact name, so keep it one line and literal.
  npmDepsHash = "sha256-1AOYW4SQ7y5/ERCYQiyDSpj2zpPS6VeBZFgzFsbigKg=";
in
buildNpmPackage {
  pname = "infisical-backend";
  inherit version src;

  # Upstream is a monorepo; only `backend/` is packaged here. The web UI is a
  # separate build (infisical-frontend.nix) that this package does not need and
  # does not reference -- the API is useful on its own, and nothing in this
  # repo's CLI touches the UI. `infisical-standalone` joins the two for anyone
  # who wants both.
  sourceRoot = "${src.name}/backend";

  # Fetcher v2 caches registry *metadata*, not just tarballs. Infisical's
  # package.json carries nested `overrides` that pin ranges rather than exact
  # versions (`eslint-plugin-import` -> `minimatch: ^3.1.2`, and similar), and
  # npm resolves those ranges during `npm ci` even though the lockfile already
  # has an answer. With v1 that resolution hits the network and the sandboxed
  # build dies on ENOTCACHED.
  npmDepsFetcherVersion = 2;

  npmDeps = fetchNpmDeps {
    src = infisicalSource.npmLock "backend";
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
    ${infisicalSource.filterLockInPlace}
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
  #
  # Deliberately WITHOUT `--legacy-peer-deps`, unlike the `npm ci` above.
  # Prune recomputes which packages are reachable and deletes the rest, and
  # under legacy resolution peer dependencies are not reachable from anything
  # -- so it removed `express-session`, which nothing declares directly and
  # `connect-redis` only asks for as a peer. `npm ci` had installed it (the
  # lockfile carries it, `"peer": true`), the build succeeded, and the server
  # then died on every start with ERR_MODULE_NOT_FOUND from inside
  # connect-redis. The flag is needed for the install's range resolution; it
  # is wrong for deciding what to keep.
  installPhase = ''
    runHook preInstall

    npm prune --omit=dev --offline --no-audit --no-fund

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
  # to check here beyond the build having produced its entrypoints and a
  # node_modules the runtime can actually resolve against.
  doCheck = false;

  # stdenv only runs `postInstallCheck` from `installCheckPhase`, and skips
  # that phase unless `doInstallCheck` is set. Without this the assertions
  # below never execute -- they read as a safety net while checking nothing.
  doInstallCheck = true;

  postInstallCheck = ''
    test -f $out/lib/infisical/dist/main.mjs
    test -f $out/lib/infisical/dist/db/knexfile.mjs
    test -f $out/lib/infisical/dist/db/auditlog-knexfile.mjs

    # The prune above decides what to delete, and peer dependencies are the
    # thing it gets wrong: nothing depends on them by name, so a wrong flag
    # drops them and the build still succeeds. The cost lands at runtime, as
    # ERR_MODULE_NOT_FOUND from inside whichever package asked for the peer.
    # Assert every required (non-optional) peer of a retained package is still
    # resolvable, so that mistake fails here instead of in a crashloop.
    ${nodejs}/bin/node -e '
      const fs = require("fs"), path = require("path");
      const root = path.join(process.env.out, "lib/infisical/node_modules");
      const missing = [];

      // Presence walk rather than require.resolve: an ESM-only package with a
      // restrictive "exports" map is unresolvable by path even when installed,
      // which would report a missing dep that is right there.
      const resolves = (from, dep) => {
        for (let dir = from; dir.startsWith(root); dir = path.dirname(dir)) {
          if (fs.existsSync(path.join(dir, "node_modules", dep))) return true;
        }
        return fs.existsSync(path.join(root, dep));
      };

      const scan = (dir) => {
        for (const name of fs.readdirSync(dir)) {
          if (name === ".bin") continue;
          const p = path.join(dir, name);
          if (name.startsWith("@")) { scan(p); continue; }
          let pkg;
          try { pkg = JSON.parse(fs.readFileSync(path.join(p, "package.json"))); }
          catch (e) { continue; }
          const meta = pkg.peerDependenciesMeta || {};
          for (const dep of Object.keys(pkg.peerDependencies || {})) {
            if (meta[dep] && meta[dep].optional) continue;
            if (!resolves(p, dep)) missing.push(name + " needs " + dep);
          }
          const nested = path.join(p, "node_modules");
          if (fs.existsSync(nested)) scan(nested);
        }
      };
      scan(root);

      if (missing.length) {
        console.error("required peer dependencies missing from the pruned tree:");
        for (const m of missing) console.error("  " + m);
        process.exit(1);
      }
    '
  '';

  meta = with lib; {
    description = "Infisical secrets-management API server";
    homepage = "https://github.com/Infisical/infisical";
    license = licenses.mit; # backend/ is MIT; ee/ is source-available
    platforms = platforms.linux;
    mainProgram = "infisical-server";
  };
}
