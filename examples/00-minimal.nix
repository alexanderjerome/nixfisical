# The smallest declaration that does something.
#
# One instance, one organization, one project, one environment, one secret.
# Everything else in this directory is an elaboration of this shape.
#
# Read this and you know the spine:
#
#   instance -> organization -> project -> environment -> folder -> secret
#
# Those are the API's own nesting levels, not ours. A secret write is
# addressed by (projectId, environment, secretPath, secretKey) and there is
# no call in the API that crosses a project or an environment. The nesting
# below is that addressing, made syntactic.
{
  infisical.instances.lab = {
    # Where the server is. Not where it runs — this module has no opinion on
    # whether the instance is the LXC down the hall or app.infisical.com.
    url = "https://infisical.example.com";

    # The organization this declaration governs. One instance can host
    # several, and they are a hard partition: an access token is scoped to
    # exactly one and sees nothing of another.
    #
    # `slug` selects it. `id` and `name` are the other two matchers, tried in
    # the order id, slug, name. Everything else under `organization` is
    # declaration rather than selection — see 20-organization.nix.
    organization.slug = "lab";

    # How the reconciler authenticates. A machine identity's client id and
    # secret, sourced the same way any other value is.
    auth.sopsFile = ./secrets/infisical-admin.yaml;

    projects.apps = {
      projectName = "apps";

      # Declaring environments at all means the reconciler passes
      # shouldCreateDefaultEnvs = false on create. Leave this out and
      # Infisical seeds Development/Staging/Production and you own three
      # environments you never asked for.
      environments.prod = {
        name = "Production";
        position = 1;
      };

      secrets.prod."/" = {
        API_KEY.sopsFile = ./secrets/apps.yaml;
      };
    };
  };
}
