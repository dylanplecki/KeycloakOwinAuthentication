using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;

namespace Owin.Security.Keycloak
{
    public class KeycloakAuthenticationOptions : AuthenticationOptions
    {
        private const string DefaultAuthenticationType = "KeycloakAuthentication";

        public KeycloakAuthenticationOptions()
            : base(DefaultAuthenticationType)
        {
        }

        /// <summary>
        /// Defines the entire URL to the Keycloak instance
        /// </summary>
        /// <remarks>
        ///   - By default, keycloak is deployed to the /auth submodule
        ///     on the webserver, which must be included in this URL
        /// </remarks>
        public string KeycloakUrl { get; set; }

        /// <summary>
        /// The Keycloak realm on which the client is located
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// OPTIONAL: The OpenID scopes to request when authenticating a user
        /// </summary>
        /// <remarks>
        ///   - All scopes should be space-delimited in a single string
        ///   - Default: "openid"
        /// </remarks>
        public string Scope { get; set; }

        /// <summary>
        /// The client ID to use for the application
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// OPTIONAL: The client secret to use for the application
        /// </summary>
        /// <remarks>
        ///   - Not required for public clients
        ///   - Default: None
        /// </remarks>
        public string ClientSecret { get; set; }

        /// <summary>
        /// OPTIONAL: The absolute URL for users to be redirected to after logout
        /// </summary>
        /// <remarks>
        ///   - Default: Base URL
        /// </remarks>
        public string PostLogoutRedirectUrl { get; set; }

        /// <summary>
        /// OPTIONAL: Choose a default identity provider to use for the application
        /// </summary>
        /// <remarks>
        ///   - The value here must be a valid IDP ID in the specified Keycloak realm
        ///   - Only this chosen IDP may be used with this application
        ///   - The Keycloak login page will not be shown when this option is non-empty
        ///   - Default: None
        /// </remarks>
        public string IdentityProvider { get; set; }

        /// <summary>
        /// OPTIONAL: Automatically refresh user tokens upon expiration
        /// </summary>
        /// <remarks>
        ///   - Default: True
        /// </remarks>
        public bool AutoTokenRefresh { get; set; } = true;

        /// <summary>
        /// OPTIONAL: Save access and ID tokens as user claims
        /// </summary>
        /// <remarks>
        ///   - Forced enabled when using 'AutoTokenRefresh'
        ///   - Default: True
        /// </remarks>
        public bool SaveTokensAsClaims { get; set; } = true;

        public string CallbackPath { get; set; }
        public string ResponseType { get; set; }
        public string SignInAsAuthenticationType { get; set; }

        public CookieAuthenticationOptions CookieAuthenticationOptions { get; set; } =
            new CookieAuthenticationOptions();
    }
}