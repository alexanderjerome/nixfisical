# The `nixfisical` CLI — bootstrap + reconcile, wrapped with the binaries it
# shells out to.
#
# `sops` is a hard runtime dependency: every secret value the reconciler
# pushes is decrypted through it, on the operator's machine, at run time.
# `git` is only needed for `bootstrap --git-commit`, but wrapping both keeps
# the tool usable from a bare `nix run` with nothing else installed.
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

  postFixup = ''
    wrapProgram $out/bin/nixfisical \
      --prefix PATH : ${lib.makeBinPath [ sops git ]}
  '';

  # No test suite yet; the import check catches the usual packaging mistakes
  # (missing module in the wheel, a dependency declared in pyproject but not
  # in `dependencies` above).
  pythonImportsCheck = [
    "nixfisical"
    "nixfisical.api"
    "nixfisical.bootstrap"
    "nixfisical.reconcile"
  ];

  meta = with lib; {
    description = "Declarative bootstrap and secret reconciliation for a self-hosted Infisical instance";
    homepage = "https://github.com/alexanderjerome/nixfisical";
    license = licenses.mit;
    mainProgram = "nixfisical";
    platforms = platforms.unix;
  };
}
