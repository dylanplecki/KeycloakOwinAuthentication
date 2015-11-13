using System;

namespace KeycloakIdentityModel.Models.Configuration
{
    public interface IKeycloakParameters
    {
        string AuthenticationType { get; }
        string KeycloakUrl { get; }
        string Realm { get; }
        string ClientId { get; }
        string ClientSecret { get; }
        string Scope { get; }
        string IdentityProvider { get; }
        string PostLogoutRedirectUrl { get; }
        bool DisableTokenSignatureValidation { get; }
        bool AllowUnsignedTokens { get; }
        bool DisableIssuerValidation { get; }
        bool DisableAudienceValidation { get; }
        TimeSpan TokenClockSkew { get; }
        bool UseRemoteTokenValidation { get; }
        int MetadataRefreshInterval { get; }
        string CallbackPath { get; }
        string ResponseType { get; }
    }
}
