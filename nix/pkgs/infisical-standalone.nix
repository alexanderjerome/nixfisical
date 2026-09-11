# `infisical-backend` plus the web UI, in one directory, because that is the
# only arrangement the server will accept.
#
# Infisical serves its own UI in-process when STANDALONE_MODE is set. It does
# not take a path for it: `backend/src/server/app.ts` computes
#
#     dir = path.join(__dirname, "../../")
#
# where `__dirname` is the directory of the running `dist/server/app.mjs`, and
# `serve-ui.ts` then roots @fastify/static at `<dir>/frontend-build`. So the
# UI has to sit next to the backend's `dist/`, at a path derived from where
# the backend's own code happens to be. There is no env var, no flag, and no
# way to point it elsewhere.
#
# Node resolves symlinks before computing `__dirname`, so `dist/` cannot be a
# symlink into infisical-backend's store path -- it would resolve back there
# and look for a `frontend-build` that is not in it. Hence the copy below.
# It is 47 MB, which buys not rebuilding the backend: adding the UI to the
# backend derivation directly would be an hour of npm and native-addon linking
# every time either side moves, for a change that is a directory of static
# files. `node_modules` is the 621 MB and stays a symlink -- nothing computes a
# directory from a file in there, and this is how `npm link` has always worked.
#
# `infisical-migrate` is the backend's own binary, unwrapped and unchanged. It
# runs Knex against the database and has no opinion about the UI.
{ lib
, runCommand
, makeWrapper
, nodejs_22
, git
, infisicalSource
, infisical-backend
, infisical-frontend
}:

let
  nodejs = nodejs_22;
  inherit (infisicalSource) version;
in
runCommand "infisical-standalone-${version}"
{
  nativeBuildInputs = [ makeWrapper ];
  inherit version;
  pname = "infisical-standalone";

  passthru = { inherit infisical-backend infisical-frontend; };

  meta = with lib; {
    description = "Infisical secrets-management server, serving its own web UI";
    homepage = "https://github.com/Infisical/infisical";
    license = licenses.mit; # backend/ and frontend/ are MIT; ee/ is source-available
    platforms = platforms.linux;
    mainProgram = "infisical-server";
  };
} ''
  mkdir -p $out/lib/infisical $out/bin

  cp -r ${infisical-backend}/lib/infisical/dist $out/lib/infisical/dist
  chmod -R u+w $out/lib/infisical/dist
  cp ${infisical-backend}/lib/infisical/package.json $out/lib/infisical/package.json

  ln -s ${infisical-backend}/lib/infisical/node_modules $out/lib/infisical/node_modules
  ln -s ${infisical-frontend} $out/lib/infisical/frontend-build

  # STANDALONE_MODE belongs to the package, not to the module that runs it:
  # this is the build that has a UI to serve, and the one without it crashes on
  # boot if the flag is set -- serve-ui.ts readFileSync's index.html when the
  # plugin registers, not when a request arrives. `--set-default` rather than
  # `--set` so an operator can still turn the UI off on a host without
  # switching packages.
  makeWrapper ${nodejs}/bin/node $out/bin/infisical-server \
    --add-flags "--enable-source-maps" \
    --add-flags "$out/lib/infisical/dist/main.mjs" \
    --set-default NODE_ENV production \
    --set-default STANDALONE_MODE true \
    --prefix PATH : ${lib.makeBinPath [ git ]}

  ln -s ${infisical-backend}/bin/infisical-migrate $out/bin/infisical-migrate

  # The three facts the paragraph at the top of this file depends on. Any of
  # them silently ceasing to be true turns into a boot-time crashloop or, worse,
  # a UI served from the wrong release.
  test -f $out/lib/infisical/dist/server/app.mjs
  test -f $out/lib/infisical/frontend-build/index.html
  test ! -L $out/lib/infisical/dist
''
