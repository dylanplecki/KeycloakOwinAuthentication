using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;

namespace Owin.Security.Keycloak
{
    public class KeycloakAuthenticationOptions : AuthenticationOptions
    {
        private const string DefaultAuthenticationType = "KeycloakAuthentication";

        public string KeycloakUrl { get; set; }

        public string Realm { get; set; }
        public string Scope { get; set; }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        public string CallbackPath { get; set; }
        public string ResponseType { get; set; }
        public string PostLogoutRedirectUrl { get; set; }

        public bool AutoTokenRefresh { get; set; } = true;
        public bool SaveTokensAsClaims { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public KeycloakAuthenticationOptions()
            : base(DefaultAuthenticationType)
        {
        }

        public string GetAuthority()
        {
            return KeycloakUrl + "/realms/" + Realm;
        }

        public string GetMetadataUrl()
        {
            return GetAuthority() + "/" + OpenIdProviderMetadataNames.Discovery;
        }
    }
}
