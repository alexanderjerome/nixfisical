# Infisical's web UI, built from the same pinned release as the backend.
#
# This is a static site and nothing else: Vite + React (upstream calls the
# workspace `frontend-v2`), whose `build` is `tsc -b && vite build` and whose
# entire output is a `dist/` of HTML, JS and assets. There is no server here,
# no Node process, nothing to run. `$out` *is* the document root -- index.html
# sits at the top of it -- because the only consumer is a symlink from
# `infisical-standalone`, and a `share/...` prefix would be one more path for
# that symlink to get wrong.
#
# Nothing serves it on its own. The backend does, in-process, out of a path it
# computes relative to its own `dist/` -- see infisical-standalone.nix, which
# exists solely to put the two in the same directory. Building this package
# alone gets you a directory of files and no way to reach them; that is fine,
# and it is why the backend remains useful and shippable without it.
#
# Kept out of `infisical-backend` deliberately. The backend is an hour of npm
# and native-addon linking; the UI is neither, and folding them into one
# derivation would mean paying for that hour every time only the UI moved.
{ lib
, buildNpmPackage
, fetchNpmDeps
, jq
, nodejs_22
, infisicalSource
}:

let
  inherit (infisicalSource) version src;

  # Half of a version bump; the other half -- the release and its source hash
  # -- is in infisical-source.nix, shared with the backend. `nix run
  # .#bump-infisical -- <version>` rewrites this in place; it matches on this
  # exact name, so keep it one line and literal.
  npmDepsHash = "sha256-yxulkWCqcx1qm4SvH20JQgfLjFsHFQI9lBoe/0E0IJo=";
in
buildNpmPackage {
  pname = "infisical-frontend";
  inherit version src;

  sourceRoot = "${src.name}/frontend";

  # Same reason as the backend: Infisical's package.json carries nested
  # `overrides` pinning ranges rather than exact versions, and npm re-resolves
  # those during `npm ci` even though the lockfile already has an answer. v1
  # caches tarballs only, so that resolution hits the network and the sandbox
  # dies on ENOTCACHED. v2 caches the registry metadata too.
  npmDepsFetcherVersion = 2;

  npmDeps = fetchNpmDeps {
    src = infisicalSource.npmLock "frontend";
    fetcherVersion = 2;
    hash = npmDepsHash;
  };

  nodejs = nodejs_22;

  nativeBuildInputs = [ jq ];

  # `.npmrc` carries `min-release-age=7`, which tells npm to refuse packages
  # published in the last week. That is aimed at `npm install` resolving new
  # versions; here every version is fixed by the lockfile and the store path,
  # so it has nothing to decide and only wants registry metadata it cannot
  # reach in a sandbox.
  postPatch = ''
    rm -f .npmrc
    ${infisicalSource.filterLockInPlace}
  '';

  # Upstream installs the frontend's dependencies with `--ignore-scripts`
  # (Dockerfile.standalone-infisical, the `frontend-dependencies` stage), and
  # so do we. Every native thing in this tree -- esbuild, rollup, @swc/core,
  # tailwind's oxide -- ships a prebuilt binary per platform and its install
  # script exists to *download* one when the prebuilt is missing. In a sandbox
  # that is a fetch that cannot happen; with the lockfile's linux binaries
  # already present it is a fetch that does not need to.
  npmFlags = [ "--ignore-scripts" ];

  # A Vite production build of a codebase this size does not fit in Node's
  # default old-space. Upstream sets the same 8 GB ceiling.
  env.NODE_OPTIONS = "--max-old-space-size=8192";

  # Stamped into the built asset filenames by vite.config.ts, which otherwise
  # falls back to the literal "0.0.1" and produces a bundle claiming to be a
  # version that was never released. Both spellings: the config reads
  # INFISICAL_PLATFORM_VERSION first and VITE_INFISICAL_PLATFORM_VERSION
  # second, and upstream sets both rather than picking.
  env.INFISICAL_PLATFORM_VERSION = version;
  env.VITE_INFISICAL_PLATFORM_VERSION = version;

  # POSTHOG_* and INTERCOM_ID are deliberately unset. Upstream's image bakes in
  # placeholder strings for them; a self-hosted instance with telemetry off
  # wants neither, and the backend hands the UI its real runtime values through
  # /runtime-ui-env.js at request time anyway.

  installPhase = ''
    runHook preInstall
    cp -r dist $out
    runHook postInstall
  '';

  doInstallCheck = true;

  # `vite build` is perfectly happy to emit an empty `dist/` if the entry
  # resolves to nothing, and the failure would then land in the backend at
  # boot, as a readFileSync of a missing index.html -- serve-ui.ts reads it
  # when the plugin registers, not when a request arrives, so a bad frontend
  # is a crashloop rather than a 404. Catch it here instead.
  postInstallCheck = ''
    test -f $out/index.html
    test -d $out/assets
    grep -q '/runtime-ui-env.js' $out/index.html
  '';

  meta = with lib; {
    description = "Infisical web UI (static build)";
    homepage = "https://github.com/Infisical/infisical";
    license = licenses.mit;
    platforms = platforms.linux;
  };
}
