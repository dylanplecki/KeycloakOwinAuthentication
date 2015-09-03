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

        public string KeycloakUrl { get; set; }
        public string Realm { get; set; }
        public string Scope { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string CallbackPath { get; set; }
        public string ResponseType { get; set; }
        public string PostLogoutRedirectUrl { get; set; }
        public bool AutoTokenRefresh { get; set; } = true;
        public bool SaveTokensAsClaims { get; set; } = true;
        public string SignInAsAuthenticationType { get; set; }

        public CookieAuthenticationOptions CookieAuthenticationOptions { get; set; } =
            new CookieAuthenticationOptions();
    }
}