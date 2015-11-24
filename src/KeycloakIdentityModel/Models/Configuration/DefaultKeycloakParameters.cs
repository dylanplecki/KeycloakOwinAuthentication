using System;

namespace KeycloakIdentityModel.Models.Configuration
{
    public class DefaultKeycloakParameters : IKeycloakParameters
    {
        public string AuthenticationType { get; set; }
        public string KeycloakUrl { get; set; }
        public string Realm { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Scope { get; set; }
        public string IdentityProvider { get; set; }
        public string PostLogoutRedirectUrl { get; set; }
        public bool DisableTokenSignatureValidation { get; set; } = false;
        public bool AllowUnsignedTokens { get; set; } = false;
        public bool DisableIssuerValidation { get; set; } = false;
        public bool DisableAudienceValidation { get; set; } = false;
        public TimeSpan TokenClockSkew { get; set; } = TimeSpan.FromSeconds(1);
        public bool UseRemoteTokenValidation { get; set; } = false;
        public TimeSpan MetadataRefreshInterval { get; set; } = TimeSpan.FromMinutes(60);
        public string CallbackPath { get; set; }
        public string ResponseType { get; set; }
    }
}
