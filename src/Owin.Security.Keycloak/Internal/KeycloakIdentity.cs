using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Threading.Tasks;
using Owin.Security.Keycloak.Models.Responses;

namespace Owin.Security.Keycloak.Internal
{
    internal class KeycloakIdentity
    {
        private readonly TokenResponse _keycloakToken;

        public KeycloakIdentity(string encodedTokenResponse)
            : this(new TokenResponse(encodedTokenResponse))
        {
        }

        public KeycloakIdentity(TokenResponse tokenResponse)
        {
            _keycloakToken = tokenResponse;
        }

        public async Task<ClaimsPrincipal> ValidateIdentity(KeycloakAuthenticationOptions options)
        {
            var uriManager = await OidcDataManager.GetCachedContext(options);
            return ValidateIdentity(options.ClientId, uriManager.GetIssuer(), uriManager.GetJwkTokens());
        }

        public ClaimsPrincipal ValidateIdentity(string audience, string issuer, IEnumerable<SecurityToken> signingKeys)
        {
            // Generate token validation parameters
            var tokenValidationParams = new TokenValidationParameters // TODO: Add more?
            {
                ValidAudience = audience,
                ValidIssuer = issuer,
                IssuerSigningTokens = signingKeys
            };

            // Decode and validate JWT (tokens)
            SecurityToken accessToken, idToken;
            var jwtHandler = new JwtSecurityTokenHandler();
            var idTokenIdentity = jwtHandler.ValidateToken(_keycloakToken.IdToken, tokenValidationParams, out idToken);
            var accessTokenIdentity = jwtHandler.ValidateToken(_keycloakToken.AccessToken, tokenValidationParams,
                out accessToken);

            // TODO: Merge identities and get roles / other info
            return null;
        }
    }
}
