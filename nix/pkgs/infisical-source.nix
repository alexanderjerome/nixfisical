# The pinned upstream release, and the two things every workspace built out of
# it needs.
#
# This file exists because there is now more than one package built from the
# Infisical monorepo -- `infisical-backend` (the API) and `infisical-frontend`
# (the web UI) -- and they are joined at runtime by `infisical-standalone`: the
# backend serves the frontend's files from inside its own process. A backend
# from one release serving a frontend from another is a mismatch nothing would
# catch at build time; the API would answer and the UI would be subtly wrong.
#
# So the version and its hash live here once, and both packages take them from
# the same place. `nix run .#bump-infisical -- <version>` rewrites the two
# bindings below; it matches on these exact names, so keep them one-per-line
# and literal.
{ lib
, fetchFromGitHub
, runCommand
, jq
}:

rec {
  version = "0.165.8";
  srcHash = "sha256-VGaGbV77VuLckTMDf0Gl5Qa7uVmfN9XuJ5mdltRpVF8=";

  src = fetchFromGitHub {
    owner = "Infisical";
    repo = "infisical";
    rev = "v${version}";
    hash = srcHash;
  };

  # `prefetch-npm-deps` fetches every entry in a lockfile; `npm ci` fetches only
  # those matching the host's os/cpu. That difference is normally invisible, but
  # the backend's lockfile pins `@infisical/quic-darwin-arm64`, `-darwin-x64`,
  # `-darwin-universal` and `-win32-x64` at versions that were never published
  # -- the registry answers 404 for all four, while the two linux builds are
  # present. So the prefetch fails on packages the build would never install.
  #
  # Dropping every optional entry that excludes linux fixes it. These packages
  # are linux-only, so on the platforms they target the filter removes exactly
  # what npm would have skipped by itself. The frontend has no unpublished
  # entries of its own, but it does carry 46 foreign esbuild/rollup/swc/oxide
  # binaries, and not fetching those is worth having anyway.
  #
  # It has to be applied in two places per workspace: to the lockfile the
  # prefetcher reads, and to the one in the unpacked source, because
  # `npmConfigHook` refuses to build when the two differ. Hence one filter
  # defined once -- if these drift the build fails with a hash mismatch that
  # says nothing about the cause.
  lockFilter = ''
    def foreignOptional:
      (.optional == true) and (has("os")) and ((.os | index("linux")) == null);
    .packages |= with_entries(select(.value | foreignOptional | not))
  '';

  # The filtered `package.json` + `package-lock.json` pair for one workspace of
  # the monorepo, as a directory `fetchNpmDeps` can be pointed at.
  npmLock = workspace: runCommand "infisical-${workspace}-npm-lock"
    {
      nativeBuildInputs = [ jq ];
    } ''
    mkdir -p $out
    cp ${src}/${workspace}/package.json $out/package.json
    jq ${lib.escapeShellArg lockFilter} \
      ${src}/${workspace}/package-lock.json > $out/package-lock.json
  '';

  # The same filter, for `postPatch` inside a workspace's source root.
  #
  # Joined rather than written as an indented string so it carries no trailing
  # newline. A `''` block would add one, and `postPatch` is part of the
  # derivation: that byte changes infisical-backend's store path and costs an
  # hour of npm and native-addon linking to rebuild a package whose behaviour
  # did not change. Tidying this into a multi-line string is not free.
  filterLockInPlace = lib.concatStringsSep "\n" [
    "jq ${lib.escapeShellArg lockFilter} package-lock.json > package-lock.json.filtered"
    "mv package-lock.json.filtered package-lock.json"
  ];
}
