using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Owin.Security.Keycloak.Internal.ClaimMapping;
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

        public async Task<ClaimsIdentity> ValidateIdentity(KeycloakAuthenticationOptions options,
            string authenticationType = null)
        {
            // Validate JWTs provided
            SecurityToken idToken = null, refreshToken = null, accessToken = null;
            var tokenHandler = new KeycloakTokenHandler();
            if (_keycloakToken.IdToken != null)
                idToken = tokenHandler.ValidateToken(_keycloakToken.IdToken, options);
            if (_keycloakToken.RefreshToken != null)
                refreshToken = tokenHandler.ValidateToken(_keycloakToken.RefreshToken, options);
            if (_keycloakToken.AccessToken != null)
            {
                if (options.UseRemoteTokenValidation)
                    accessToken = await KeycloakTokenHandler.ValidateTokenRemote(_keycloakToken.AccessToken, options);
                else
                    accessToken = tokenHandler.ValidateToken(_keycloakToken.AccessToken, options);
            }

            // Create the new claims identity
            return // TODO: Convert to MS claims parsing in token handler
                new ClaimsIdentity(
                    GenerateJwtClaims(accessToken as JwtSecurityToken, idToken as JwtSecurityToken,
                        refreshToken as JwtSecurityToken, options),
                    authenticationType ?? options.SignInAsAuthenticationType);
        }

        protected IEnumerable<Claim> GenerateJwtClaims(JwtSecurityToken accessToken, JwtSecurityToken idToken,
            JwtSecurityToken refreshToken, KeycloakAuthenticationOptions options)
        {
            // Add generic claims
            yield return new Claim(Constants.ClaimTypes.AuthenticationType, options.AuthenticationType);
            yield return new Claim(Constants.ClaimTypes.Version, Global.GetVersion());

            // Save the recieved tokens as claims
            if (options.SaveTokensAsClaims)
            {
                if (_keycloakToken.IdToken != null)
                    yield return new Claim(Constants.ClaimTypes.IdToken, _keycloakToken.IdToken);
                if (_keycloakToken.AccessToken != null)
                    yield return new Claim(Constants.ClaimTypes.AccessToken, _keycloakToken.AccessToken);
                if (_keycloakToken.RefreshToken != null)
                    yield return new Claim(Constants.ClaimTypes.RefreshToken, _keycloakToken.RefreshToken);
            }

            // Add OIDC token claims
            var jsonId = options.ClientId;
            if (_keycloakToken.IdToken != null)
                foreach (
                    var claim in ProcessOidcToken(idToken.GetPayloadJObject(), ClaimMappings.IdTokenMappings, jsonId))
                    yield return claim;
            if (_keycloakToken.AccessToken != null)
                foreach (
                    var claim in
                        ProcessOidcToken(accessToken.GetPayloadJObject(), ClaimMappings.AccessTokenMappings, jsonId)
                    )
                    yield return claim;
            if (_keycloakToken.RefreshToken != null)
                foreach (
                    var claim in
                        ProcessOidcToken(refreshToken.GetPayloadJObject(), ClaimMappings.RefreshTokenMappings, jsonId))
                    yield return claim;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IEnumerable<Claim> ProcessOidcToken(JObject webToken, IEnumerable<ClaimLookup> claimMappings,
            string jsonId)
        {
            // Process claim mappings
            return claimMappings.SelectMany(lookupClaim => lookupClaim.ProcessClaimLookup(webToken, jsonId));
        }
    }
}