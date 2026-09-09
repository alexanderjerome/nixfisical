# `nix run .#bump-infisical -- <version>` — move infisical-backend.nix to a new
# upstream release.
#
# A bump needs three values and two of them are content hashes, which Nix will
# not compute for you: the only way to learn a fixed-output derivation's hash is
# to build it with a wrong one and read the mismatch. Doing that by hand is four
# copy-pastes with a build between each, and getting one wrong fails much later
# with an error that names the hash and not the mistake. Hence a script.
#
# It resolves each hash from its own attribute (`.src`, `.npmDeps`) rather than
# by building the whole package and parsing the first failure, so the source
# tarball is fetched once and no npm install happens until both hashes are real.
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

    file=nix/pkgs/infisical-backend.nix
    if [ ! -f "$file" ]; then
      echo "bump-infisical: run me from the root of the nixfisical checkout" >&2
      echo "  (expected to find $file)" >&2
      exit 1
    fi

    # `path:` rather than `.` so the working tree is read literally. A bump is
    # exactly when the tree is dirty, and a flake ref would ignore any of these
    # edits that git does not yet track.
    flake="path:$PWD"

    # All-zero SHA-256. Any wrong hash would do; this one is recognisably not a
    # real one if the script dies halfway and leaves it in the file.
    fake="${lib.fakeHash}"

    set_field() {
      # Anchored to two-space indent and the exact binding name, so `srcHash`
      # cannot match `npmDepsHash` and neither can match a hash in a comment.
      sed -i "s|^  $1 = \"[^\"]*\";$|  $1 = \"$2\";|" "$file"
      if ! grep -q "^  $1 = \"$2\";$" "$file"; then
        echo "bump-infisical: failed to rewrite '$1' in $file." >&2
        echo "  The binding must be a single literal line: '  $1 = \"...\";'" >&2
        exit 1
      fi
    }

    # Build an attribute expected to fail on a hash mismatch, and print the hash
    # Nix says it actually got.
    resolve() {
      local attr=$1 out
      if out=$(nix build --no-link "$flake#infisical-backend.$attr" 2>&1); then
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

    set_field version "$version"

    # Order matters: npmDeps derives from the fetched source, so a fake srcHash
    # would make the npmDeps build fail on the source and report the source's
    # hash. Settle the source first.
    echo "  resolving srcHash (fetching v$version) ..."
    set_field srcHash "$fake"
    src_hash=$(resolve src)
    set_field srcHash "$src_hash"
    echo "  srcHash     = $src_hash"

    echo "  resolving npmDepsHash (fetching the npm tree) ..."
    set_field npmDepsHash "$fake"
    npm_hash=$(resolve npmDeps)
    set_field npmDepsHash "$npm_hash"
    echo "  npmDepsHash = $npm_hash"

    echo ""
    echo "$file updated. Not built and not committed — next:"
    echo "  nix build $flake#infisical-backend"
    echo "  git diff $file"
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
