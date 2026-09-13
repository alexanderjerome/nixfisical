# The `nixfisical` CLI — bootstrap + reconcile, wrapped with the binaries it
# shells out to.
#
# `sops` is a hard runtime dependency: every secret value the reconciler
# pushes is decrypted through it, on the operator's machine, at run time.
# `git` is only needed for `bootstrap --git-commit`, but wrapping both keeps
# the tool usable from a bare `nix run` with nothing else installed.
#
# `psql` is deliberately NOT wrapped. Only `sync-access --create-missing-groups`
# shells out to it, that flag is off by default and most fleets never set it,
# and postgresql is a large closure to hang on every user of this tool for a
# documented escape hatch. `--prefix PATH` leaves the caller's own PATH intact,
# so an operator who has psql gets it and one who does not gets an error
# naming the binary.
{ lib
, python3Packages
, sops
, git
, makeWrapper
}:

python3Packages.buildPythonApplication rec {
  pname = "nixfisical";
  version = "0.1.0";
  pyproject = true;

  src = ../../pkgs/nixfisical;

  build-system = [ python3Packages.setuptools ];

  dependencies = with python3Packages; [
    click
    httpx
    pyyaml
  ];

  nativeBuildInputs = [ makeWrapper ];

  # The suite is deliberately offline-only: no server, no network. It covers
  # the handful of functions whose failure mode is silent rather than loud — an
  # admin block landing in the wrong estate's file, a find rule drifting from
  # the create rule and minting a duplicate organization on every run. Anything
  # needing a live instance is not a check, it is an operation.
  #
  # `sops` is here for exactly one suite. `set_keys` REPLACES an encrypted file
  # holding an estate's secrets, and its dangerous outcomes — a store that no
  # longer decrypts, or one quietly missing the keys this run did not write —
  # are invisible to a test that stubs sops out, because the risk lives in the
  # part the stub replaces. It runs against a throwaway age key in a tmpdir, so
  # it is still offline. The suite skips itself when sops is absent, which is
  # why this line is load-bearing: without it the tests do not fail, they
  # silently stop running.
  nativeCheckInputs = [ python3Packages.pytestCheckHook sops ];

  postFixup = ''
    wrapProgram $out/bin/nixfisical \
      --prefix PATH : ${lib.makeBinPath [ sops git ]}
  '';

  # The import check is still worth its keep alongside the tests: it catches
  # the packaging mistakes the tests cannot see, because the tests import a
  # module or two and a missing one elsewhere in the wheel stays missing.
  pythonImportsCheck = [
    "nixfisical"
    "nixfisical.access"
    "nixfisical.api"
    "nixfisical.bootstrap"
    "nixfisical.generate"
    "nixfisical.license"
    "nixfisical.pull"
    "nixfisical.reconcile"
    "nixfisical.store"
  ];

  meta = with lib; {
    description = "Declarative bootstrap and secret reconciliation for a self-hosted Infisical instance";
    homepage = "https://github.com/jeirslab/nixfisical";
    license = licenses.mit;
    mainProgram = "nixfisical";
    platforms = platforms.unix;
  };
}
