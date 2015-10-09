using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin.Security.Keycloak.Middleware;

namespace Owin.Security.Keycloak
{
    public static class AppBuilderExtension
    {
        public static IAppBuilder UseKeycloakAuthentication(this IAppBuilder app, KeycloakAuthenticationOptions options)
        {
            // Only enable cookies if 'ForceBearerTokenAuth' is disabled
            if (!options.ForceBearerTokenAuth)
            {
                // Check for invalid null options
                if (options.CookieAuthenticationOptions == null)
                    options.CookieAuthenticationOptions = new CookieAuthenticationOptions();

                // Validate some required options here
                ValidateCookieOptions(options);

                app.UseCookieAuthentication(options.CookieAuthenticationOptions);
                app.Use(typeof (KeycloakAuthenticationMiddleware), app, options);
                app.SetDefaultSignInAsAuthenticationType(options.CookieAuthenticationOptions.AuthenticationType);
            }

            return app;
        }

        private static void ValidateCookieOptions(KeycloakAuthenticationOptions options)
        {
            var cookieOptions = options.CookieAuthenticationOptions;

            cookieOptions.AuthenticationType += "." + options.AuthenticationType;
            if (string.IsNullOrEmpty(cookieOptions.CookieName))
                cookieOptions.CookieName = "Store." + cookieOptions.AuthenticationType;

            cookieOptions.Provider = new CookieAuthenticationProvider
            {
                OnValidateIdentity = KeycloakAuthenticationHandler.ValidateCookieIdentity
            };
        }
    }
}