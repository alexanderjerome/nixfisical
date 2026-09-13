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
#
# `minimal = true` builds the same source for a different audience: the hosts
# that inject secrets directly. They run `nixfisical-agent`, which talks to the
# API over httpx and touches neither sops nor git — so wrapping it against both
# would put roughly a quarter-gigabyte of operator tooling into the closure of
# every host in the fleet, to be pulled over the wire on each deploy, for
# nothing. The operator CLI is removed rather than left unwrapped: an
# unwrapped `nixfisical` on a host would run, find no `sops` on PATH, and fail
# somewhere inside a decrypt with an error about a missing binary.
{ lib
, python3Packages
, sops
, git
, makeWrapper
, minimal ? false
}:

python3Packages.buildPythonApplication rec {
  pname = if minimal then "nixfisical-agent" else "nixfisical";
  version = "0.1.0";
  pyproject = true;

  src = ../../pkgs/nixfisical;

  build-system = [ python3Packages.setuptools ];

  dependencies = with python3Packages; [
    click
    httpx
    pyyaml
  ];

  nativeBuildInputs = lib.optional (!minimal) makeWrapper;

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
  nativeCheckInputs = [ python3Packages.pytestCheckHook ] ++ lib.optional (!minimal) sops;

  # The minimal build ships `nixfisical-agent` alone. Deleting the operator CLI
  # here rather than filtering `project.scripts` keeps one pyproject and one
  # source tree — the two builds differ in what is installed, not in what they
  # are.
  postFixup =
    if minimal then ''
      rm -f $out/bin/nixfisical
    '' else ''
      wrapProgram $out/bin/nixfisical \
        --prefix PATH : ${lib.makeBinPath [ sops git ]}
    '';

  # The import check is still worth its keep alongside the tests: it catches
  # the packaging mistakes the tests cannot see, because the tests import a
  # module or two and a missing one elsewhere in the wheel stays missing.
  pythonImportsCheck = [
    "nixfisical"
    "nixfisical.access"
    "nixfisical.agent"
    "nixfisical.api"
    "nixfisical.bootstrap"
    "nixfisical.generate"
    "nixfisical.license"
    "nixfisical.provision"
    "nixfisical.pull"
    "nixfisical.reconcile"
    "nixfisical.store"
  ];

  meta = with lib; {
    description =
      if minimal
      then "Host-side agent that fetches this machine's secrets from Infisical"
      else "Declarative bootstrap and secret reconciliation for a self-hosted Infisical instance";
    homepage = "https://github.com/jeirslab/nixfisical";
    license = licenses.mit;
    mainProgram = if minimal then "nixfisical-agent" else "nixfisical";
    platforms = platforms.unix;
  };
}
