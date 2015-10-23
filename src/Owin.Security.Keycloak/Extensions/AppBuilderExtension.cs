using Owin.Security.Keycloak.Middleware;

namespace Owin.Security.Keycloak
{
    public static class AppBuilderExtension
    {
        public static IAppBuilder UseKeycloakAuthentication(this IAppBuilder app, KeycloakAuthenticationOptions options)
        {
            app.Use(typeof (KeycloakAuthenticationMiddleware), app, options);
            return app;
        }
    }
}