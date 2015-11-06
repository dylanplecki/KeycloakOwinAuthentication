using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using KeycloakIdentityModel.Extensions;
using KeycloakIdentityModel.Models.Configuration;
using KeycloakIdentityModel.Models.Messages;
using KeycloakIdentityModel.Models.Responses;
using KeycloakIdentityModel.Utilities;
using KeycloakIdentityModel.Utilities.ClaimMapping;
using Newtonsoft.Json.Linq;

namespace KeycloakIdentityModel
{
    public class KeycloakIdentity
    {
        public enum ValidationStatus
        {
            Invalid,
            Expired,
            Valid
        }

        private readonly string _accessToken;
        private readonly string _idToken;
        private readonly string _refreshToken;

        /// <summary>
        /// Load a new identity from a token endpoint response string
        /// </summary>
        /// <param name="encodedTokenResponse"></param>
        public KeycloakIdentity(string encodedTokenResponse)
            : this(new TokenResponse(encodedTokenResponse))
        {
        }

        /// <summary>
        /// Load a new identity from the token endpoint response JSON
        /// </summary>
        /// <param name="tokenResponseJson"></param>
        public KeycloakIdentity(JObject tokenResponseJson)
            : this(new TokenResponse(tokenResponseJson))
        {
        }

        /// <summary>
        /// Load a new identity from a token response
        /// </summary>
        /// <param name="tokenResponse"></param>
        public KeycloakIdentity(TokenResponse tokenResponse)
            : this(tokenResponse.AccessToken, tokenResponse.IdToken, tokenResponse.RefreshToken)
        {
        }

        /// <summary>
        /// Load a new identity from any combination of JWTs
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="idToken"></param>
        /// <param name="refreshToken"></param>
        public KeycloakIdentity(string accessToken, string idToken, string refreshToken)
        {
            _accessToken = accessToken;
            _idToken = idToken;
            _refreshToken = refreshToken;
        }

        /// <summary>
        /// Validate and parse the current keycloak identity
        /// </summary>
        /// <param name="options"></param>
        /// <param name="authenticationType"></param>
        /// <returns>Identity</returns>
        public async Task<ClaimsIdentity> ValidateIdentity(IKeycloakSettings options,
            string authenticationType = null)
        {
            // Validate JWTs provided
            SecurityToken idToken = null, refreshToken = null, accessToken = null;
            var tokenHandler = new KeycloakTokenHandler();
            if (_idToken != null)
                idToken = tokenHandler.ValidateToken(_idToken, options);
            if (_refreshToken != null)
                refreshToken = tokenHandler.ValidateToken(_refreshToken, options);
            if (_accessToken != null)
            {
                if (options.UseRemoteTokenValidation)
                    accessToken = await KeycloakTokenHandler.ValidateTokenRemote(_accessToken, options);
                else
                    accessToken = tokenHandler.ValidateToken(_accessToken, options);
            }

            // Create the new claims identity
            return // TODO: Convert to MS claims parsing in token handler
                new ClaimsIdentity(
                    GenerateJwtClaims(accessToken as JwtSecurityToken, idToken as JwtSecurityToken,
                        refreshToken as JwtSecurityToken, options),
                    authenticationType ?? options.SignInAsAuthenticationType);
        }

        /// <summary>
        /// Validate a claims identity as a keycloak identity
        /// </summary>
        /// <param name="identity"></param>
        /// <returns></returns>
        public static ValidationStatus ValidateIdentity(ClaimsIdentity identity)
        {
            var claimLookup = identity.Claims.ToLookup(c => c.Type, c => c.Value);

            var version = claimLookup[Constants.ClaimTypes.Version].FirstOrDefault();
            var authType = claimLookup[Constants.ClaimTypes.AuthenticationType].FirstOrDefault();
            var refreshToken = claimLookup[Constants.ClaimTypes.RefreshToken].FirstOrDefault();

            var accessTokenExpiration =
                claimLookup[Constants.ClaimTypes.AccessTokenExpiration].FirstOrDefault();
            var refreshTokenExpiration =
                claimLookup[Constants.ClaimTypes.RefreshTokenExpiration].FirstOrDefault();
            var refreshTokenExpDate = DateTime.Parse(refreshTokenExpiration, CultureInfo.InvariantCulture);

            if (refreshToken == null || authType == null || version == null || accessTokenExpiration == null ||
                refreshTokenExpiration == null || refreshTokenExpDate <= DateTime.Now || !Global.CheckVersion(version))
                return ValidationStatus.Invalid;
            if (DateTime.Parse(accessTokenExpiration, CultureInfo.InvariantCulture) <= DateTime.Now)
                return ValidationStatus.Expired;
            return ValidationStatus.Valid;
        }

        /// <summary>
        /// Validate a claims identity as a keycloak identity and refresh the information if expired
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="options"></param>
        /// <param name="baseUri"></param>
        /// <returns></returns>
        public static Task<ClaimsIdentity> ValidateAndRefreshIdentity(ClaimsIdentity identity,
            IKeycloakSettings options, Uri baseUri)
        {
            switch (ValidateIdentity(identity))
            {
                case ValidationStatus.Invalid:
                    throw new AuthenticationException();
                case ValidationStatus.Expired:
                    var message = new RefreshAccessTokenMessage(baseUri, options,
                        identity.Claims.First(c => c.Type == Constants.ClaimTypes.RefreshToken).Value);
                    return message.ExecuteAsync();
                case ValidationStatus.Valid:
                    return Task.FromResult<ClaimsIdentity>(null);
                default:
                    throw new Exception("Unknown error occurred");
            }
        }

        protected IEnumerable<Claim> GenerateJwtClaims(JwtSecurityToken accessToken, JwtSecurityToken idToken,
            JwtSecurityToken refreshToken, IKeycloakSettings options)
        {
            // Add generic claims
            yield return new Claim(Constants.ClaimTypes.AuthenticationType, options.AuthenticationType);
            yield return new Claim(Constants.ClaimTypes.Version, Global.GetVersion());

            // Save the recieved tokens as claims
            if (options.SaveTokensAsClaims)
            {
                if (_idToken != null)
                    yield return new Claim(Constants.ClaimTypes.IdToken, _idToken);
                if (_accessToken != null)
                    yield return new Claim(Constants.ClaimTypes.AccessToken, _accessToken);
                if (_refreshToken != null)
                    yield return new Claim(Constants.ClaimTypes.RefreshToken, _refreshToken);
            }

            // Add OIDC token claims
            var jsonId = options.ClientId;
            if (_idToken != null)
                foreach (
                    var claim in ProcessOidcToken(idToken.GetPayloadJObject(), ClaimMappings.IdTokenMappings, jsonId))
                    yield return claim;
            if (_accessToken != null)
                foreach (
                    var claim in
                        ProcessOidcToken(accessToken.GetPayloadJObject(), ClaimMappings.AccessTokenMappings, jsonId)
                    )
                    yield return claim;
            if (_refreshToken != null)
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