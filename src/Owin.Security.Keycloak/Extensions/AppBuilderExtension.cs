using Owin.Security.Keycloak.Middleware;
using Owin;

namespace Owin.Security.Keycloak
{
    public static class AppBuilderExtension
    {
        public static IAppBuilder UseKeycloakAuthentication(this IAppBuilder app, KeycloakAuthenticationOptions options)
        {
            return app.Use(typeof(KeycloakAuthenticationMiddleware), app, options);
        }
    }
}
