# `nix run .#bump-infisical -- <version>` — move the pinned Infisical release.
#
# A bump needs four values and three of them are content hashes, which Nix will
# not compute for you: the only way to learn a fixed-output derivation's hash is
# to build it with a wrong one and read the mismatch. Doing that by hand is six
# copy-pastes with a build between each, and getting one wrong fails much later
# with an error that names the hash and not the mistake. Hence a script.
#
# The four live in three files, because the release is shared and the npm trees
# are not:
#
#   infisical-source.nix     version, srcHash   (the release, shared)
#   infisical-backend.nix    npmDepsHash        (the API's npm tree)
#   infisical-frontend.nix   npmDepsHash        (the web UI's npm tree)
#
# Both npm hashes have to move together. They are derived from lockfiles inside
# the same source tarball, so leaving one behind is not a stale-but-working
# pin -- it is a hash mismatch against a tarball that no longer contains what
# the hash was taken from, and the build fails with no hint that a bump is the
# reason.
#
# It resolves each hash from its own attribute (`.src`, `.npmDeps`) rather than
# by building whole packages and parsing the first failure, so the source
# tarball is fetched once and no npm install happens until every hash is real.
{ lib, writeShellApplication, nix, gnused, coreutils }:

writeShellApplication {
  name = "bump-infisical";
  runtimeInputs = [ nix gnused coreutils ];
  text = ''
    version=''${1:-}
    if [ -z "$version" ]; then
      echo "usage: bump-infisical <version>      # e.g. 0.166.0, no leading v" >&2
      exit 1
    fi
    version=''${version#v}

    source_file=nix/pkgs/infisical-source.nix
    backend_file=nix/pkgs/infisical-backend.nix
    frontend_file=nix/pkgs/infisical-frontend.nix

    for f in "$source_file" "$backend_file" "$frontend_file"; do
      if [ ! -f "$f" ]; then
        echo "bump-infisical: run me from the root of the nixfisical checkout" >&2
        echo "  (expected to find $f)" >&2
        exit 1
      fi
    done

    # `path:` rather than `.` so the working tree is read literally. A bump is
    # exactly when the tree is dirty, and a flake ref would ignore any of these
    # edits that git does not yet track.
    flake="path:$PWD"

    # All-zero SHA-256. Any wrong hash would do; this one is recognisably not a
    # real one if the script dies halfway and leaves it in a file.
    fake="${lib.fakeHash}"

    set_field() {
      local file=$1 name=$2 value=$3
      # Anchored to two-space indent and the exact binding name, so `srcHash`
      # cannot match `npmDepsHash` and neither can match a hash in a comment.
      sed -i "s|^  $name = \"[^\"]*\";$|  $name = \"$value\";|" "$file"
      if ! grep -q "^  $name = \"$value\";$" "$file"; then
        echo "bump-infisical: failed to rewrite '$name' in $file." >&2
        echo "  The binding must be a single literal line: '  $name = \"...\";'" >&2
        exit 1
      fi
    }

    # Build an attribute expected to fail on a hash mismatch, and print the hash
    # Nix says it actually got.
    resolve() {
      local attr=$1 out
      if out=$(nix build --no-link "$flake#$attr" 2>&1); then
        echo "bump-infisical: $attr built with the placeholder hash." >&2
        echo "  That should be impossible; refusing to guess." >&2
        exit 1
      fi
      # A mismatch reports both 'specified:' and 'got:'; take the latter.
      local got
      got=$(printf '%s\n' "$out" \
        | sed -n 's/.*got: *\(sha256-[A-Za-z0-9+/=]*\).*/\1/p' | tail -n 1)
      if [ -z "$got" ]; then
        echo "bump-infisical: no hash mismatch in the output for '$attr'." >&2
        echo "  The build failed for some other reason:" >&2
        printf '%s\n' "$out" | tail -n 30 >&2
        exit 1
      fi
      printf '%s' "$got"
    }

    echo "bump-infisical: $version"

    set_field "$source_file" version "$version"

    # Order matters: every npmDeps derives from the fetched source, so a fake
    # srcHash would make those builds fail on the source and report the
    # source's hash. Settle the source first.
    echo "  resolving srcHash (fetching v$version) ..."
    set_field "$source_file" srcHash "$fake"
    src_hash=$(resolve infisical-backend.src)
    set_field "$source_file" srcHash "$src_hash"
    echo "  srcHash              = $src_hash"

    echo "  resolving the backend npmDepsHash ..."
    set_field "$backend_file" npmDepsHash "$fake"
    backend_hash=$(resolve infisical-backend.npmDeps)
    set_field "$backend_file" npmDepsHash "$backend_hash"
    echo "  backend  npmDepsHash = $backend_hash"

    echo "  resolving the frontend npmDepsHash ..."
    set_field "$frontend_file" npmDepsHash "$fake"
    frontend_hash=$(resolve infisical-frontend.npmDeps)
    set_field "$frontend_file" npmDepsHash "$frontend_hash"
    echo "  frontend npmDepsHash = $frontend_hash"

    echo ""
    echo "Three files updated. Nothing built and nothing committed — next:"
    echo "  nix build $flake#infisical-standalone   # builds all three"
    echo "  git diff $source_file $backend_file $frontend_file"
    echo ""
    echo "Read upstream's release notes for new migrations before deploying:"
    echo "  https://github.com/Infisical/infisical/releases/tag/v$version"
  '';

  meta = with lib; {
    description = "Bump nixfisical's pinned Infisical release and its hashes";
    license = licenses.mit;
    mainProgram = "bump-infisical";
  };
}
