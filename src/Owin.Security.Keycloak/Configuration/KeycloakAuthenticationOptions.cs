using System;
using KeycloakIdentityModel.Models.Configuration;
using Microsoft.Owin.Security;

namespace Owin.Security.Keycloak
{
    public class KeycloakAuthenticationOptions : AuthenticationOptions, IKeycloakParameters
    {
        private const string DefaultAuthenticationType = "KeycloakAuthentication";

        public KeycloakAuthenticationOptions()
            : base(DefaultAuthenticationType)
        {
        }

        /// <summary>
        ///     Defines the entire URL to the Keycloak instance
        /// </summary>
        /// <remarks>
        ///     - By default, keycloak is deployed to the /auth submodule
        ///     on the webserver, which must be included in this URL
        /// </remarks>
        public string KeycloakUrl { get; set; }

        /// <summary>
        ///     The Keycloak realm on which the client is located
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        ///     The client ID to use for the application
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        ///     OPTIONAL: The client secret to use for the application
        /// </summary>
        /// <remarks>
        ///     - Not required for public clients
        ///     - Default: None
        /// </remarks>
        public string ClientSecret { get; set; }

        /// <summary>
        ///     OPTIONAL: The OpenID scopes to request when authenticating a user
        /// </summary>
        /// <remarks>
        ///     - All scopes should be space-delimited in a single string
        ///     - Default: "openid"
        /// </remarks>
        public string Scope { get; set; }

        /// <summary>
        ///     OPTIONAL: Choose a default identity provider to use for the application
        /// </summary>
        /// <remarks>
        ///     - The value here must be a valid IDP ID in the specified Keycloak realm
        ///     - Only this chosen IDP may be used with this application
        ///     - The Keycloak login page will not be shown when this option is non-empty
        ///     - Default: None
        /// </remarks>
        public string IdentityProvider { get; set; }

        /// <summary>
        ///     OPTIONAL: The absolute or relative URL for users to be redirected to after logout
        /// </summary>
        /// <remarks>
        ///     - Default: Application base URL
        /// </remarks>
        public string PostLogoutRedirectUrl { get; set; }

        /// <summary>
        ///     OPTIONAL: Defines the virtual root of the current application
        /// </summary>
        /// <remarks>
        ///     - For instance, if using a virtual directory in IIS such as "/secure",
        ///     this option would be "/secure"
        ///     - Default: "/"
        /// </remarks>
        public string VirtualDirectory { get; set; }

        /// <summary>
        ///     OPTIONAL: Whether to use the Web API authentication mode via bearer tokens
        ///     in the authentication header instead of interactive logins
        /// </summary>
        /// <remarks>
        ///     - This will auto-enable 'EnableBearerTokenAuth' and 'ForceBearerTokenAuth',
        ///     both of which cannot be switched off in this mode
        ///     - Default: False
        /// </remarks>
        public bool EnableWebApiMode { get; set; } = false;

        /// <summary>
        ///     OPTIONAL: The persistent sign-in mechanism used by the extension
        /// </summary>
        /// <remarks>
        ///     - Required for any session-based usage
        ///     - Default: Null
        /// </remarks>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        ///     OPTIONAL.ADV: Set the expiration time for the SignInAsAuthentication method
        /// </summary>
        /// <remarks>
        ///     - Default: 30 minutes
        /// </remarks>
        public TimeSpan SignInAsAuthenticationExpiration { get; set; } = TimeSpan.FromMinutes(30);

        /// <summary>
        ///     OPTIONAL.ADV: Allow authentication via the bearer token authorization header
        /// </summary>
        /// <remarks>
        ///     - Forced enabled when using 'ForceBearerTokenAuth'
        ///     - Default: False
        /// </remarks>
        public bool EnableBearerTokenAuth { get; set; } = false;

        /// <summary>
        ///     OPTIONAL.ADV: Force all authentication to be done via 'BearerTokenAuth' (above)
        /// </summary>
        /// <remarks>
        ///     - If an inbound request does not present a valid bearer token,
        ///     a 403 error will be issued.
        ///     - Default: False
        /// </remarks>
        public bool ForceBearerTokenAuth { get; set; } = false;

        /// <summary>
        ///     OPTIONAL.ADV: Whether to check for valid token signatures before accepting
        /// </summary>
        /// <remarks>
        ///     - If enabled, this will create a MASSIVE security hole
        ///     - Default: False
        /// </remarks>
        public bool DisableTokenSignatureValidation { get; set; } = false;

        /// <summary>
        ///     OPTIONAL.ADV: Whether to allow the extension to accept unsigned tokens
        /// </summary>
        /// <remarks>
        ///     - If enabled, this will create a MASSIVE security hole
        ///     - Default: False
        /// </remarks>
        public bool AllowUnsignedTokens { get; set; } = false;

        /// <summary>
        ///     OPTIONAL.ADV: Whether to disable the validation of the issuer of any returned token
        /// </summary>
        /// <remarks>
        ///     - Default: False
        /// </remarks>
        public bool DisableIssuerValidation { get; set; } = false;

        /// <summary>
        ///     OPTIONAL.ADV: Whether to disable the validation of the audience (app) of any returned token
        /// </summary>
        /// <remarks>
        ///     - Default: False
        /// </remarks>
        public bool DisableAudienceValidation { get; set; } = false;

        /// <summary>
        ///     OPTIONAL.ADV: The maximum grace time span for expired tokens to be accepted
        /// </summary>
        /// <remarks>
        ///     - Default: 2 seconds
        /// </remarks>
        public TimeSpan TokenClockSkew { get; set; } = TimeSpan.FromSeconds(2);

        /// <summary>
        ///     OPTIONAL.ADV: Whether to enable token validation via the Keycloak server
        /// </summary>
        /// <remarks>
        ///     - Enabling this option will require an HTTP call to the Keycloak server
        ///     on every request with a bearer token, or when new tokens are requested
        ///     - Enabling this option will also allow changes on the Keycloak server to
        ///     be seen by the end user immediately, ie. assigning a new role to a user
        ///     - Default: false
        /// </remarks>
        public bool UseRemoteTokenValidation { get; set; } = false;

        /// <summary>
        ///     OPTIONAL.ADV: The time interval for the OIDC metadata to refresh
        /// </summary>
        /// <remarks>
        ///     - User TimeSpace.MaxValue for no refreshing, and TimeSpace.Zero to always refresh
        ///     - Default: 60 minutes
        /// </remarks>
        public TimeSpan MetadataRefreshInterval { get; set; } = TimeSpan.FromMinutes(60);

        public string CallbackPath { get; set; }
        public string ResponseType { get; set; }
    }
}