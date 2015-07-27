using Newtonsoft.Json;

namespace Owin.Security.Keycloak
{
    internal interface IKeycloakOptions
    {
        [JsonProperty(Required = Required.Always)]
        string AuthenticationType { get; }

        string KeycloakUrl { get; }
        string Realm { get; }
        string Scope { get; }

        string ClientId { get; }
        string ClientSecret { get; }

        string CallbackPath { get; }
        string ResponseType { get; }
        string PostLogoutRedirectUrl { get; }

        bool AutoTokenRefresh { get; }
        bool SaveTokensAsClaims { get; }

        string SignInAsAuthenticationType { get; }
    }
}
