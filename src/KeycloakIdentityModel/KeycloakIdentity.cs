using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Threading;
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
        private JwtSecurityToken _accessToken;
        private JwtSecurityToken _idToken;
        private JwtSecurityToken _refreshToken;

        private readonly IKeycloakParameters _parameters;

        private readonly SemaphoreSlim _cachedIdentityLock = new SemaphoreSlim(1);
        private ClaimsIdentity _cachedIdentity;

        /// <summary>
        ///     Load a new Keycloak-based identity
        /// </summary>
        /// <param name="parameters"></param>
        public KeycloakIdentity(IKeycloakParameters parameters)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            _parameters = parameters;
        }

        /// <summary>
        ///     Import a new identity from a ClaimsIdentity
        /// </summary>
        /// <param name="identity"></param>
        /// <returns></returns>
        public Task ImportClaimsIdentity(ClaimsIdentity identity)
        {
            var claimLookup = identity.Claims.ToLookup(c => c.Type, c => c.Value);

            var refreshToken = claimLookup[Constants.ClaimTypes.RefreshToken].FirstOrDefault();
            var idToken = claimLookup[Constants.ClaimTypes.IdToken].FirstOrDefault();
            var accessToken = claimLookup[Constants.ClaimTypes.AccessToken].FirstOrDefault();

            return ImportJwt(accessToken, idToken, refreshToken);
        }

        /// <summary>
        ///     Import a new identity from a TokenResponse message
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public Task ImportTokenResponse(TokenResponse message)
        {
            return ImportJwt(message.AccessToken, message.IdToken, message.RefreshToken);
        }

        /// <summary>
        ///     Import a new identity from a set of JWTs
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="idToken"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        public async Task ImportJwt(string accessToken, string idToken, string refreshToken)
        {
            // Validate JWTs provided
            JwtSecurityToken idSecurityToken = null, refreshSecurityToken = null, accessSecurityToken;
            var tokenHandler = new KeycloakTokenHandler();

            if (idToken != null)
                idSecurityToken = tokenHandler.ValidateToken(idToken, _parameters) as JwtSecurityToken;

            if (refreshToken != null)
                refreshSecurityToken = tokenHandler.ValidateToken(refreshToken, _parameters) as JwtSecurityToken;

            if (_parameters.UseRemoteTokenValidation)
                accessSecurityToken =
                    await KeycloakTokenHandler.ValidateTokenRemote(accessToken, _parameters) as
                        JwtSecurityToken;
            else
                accessSecurityToken = tokenHandler.ValidateToken(accessToken, _parameters) as JwtSecurityToken;

            if (accessSecurityToken == null) throw new Exception("Internal error: Invalid access token; valid required");

            // Create the new claims identity
            // TODO: Convert to MS claims parsing in token handler
            var identity = new ClaimsIdentity(GenerateJwtClaims(accessSecurityToken, idSecurityToken, refreshSecurityToken),
                _parameters.AuthenticationType);

            // Save to this
            _cachedIdentity = identity;
            _idToken = idSecurityToken;
            _accessToken = accessSecurityToken;
            _refreshToken = refreshSecurityToken;
        }

        /// <summary>
        ///     Validate and generate the current keycloak identity safely (without exceptions)
        /// </summary>
        /// <returns>Identity (null on invalid identity)</returns>
        public Task<ClaimsIdentity> TryGenerateIdentity()
        {
            try
            {
                return GenerateIdentity();
            }
            catch (Exception)
            {
                return Task.FromResult<ClaimsIdentity>(null);
            }
        }

        /// <summary>
        ///     Validate and generate the current keycloak identity
        /// </summary>
        /// <returns>Identity</returns>
        public async Task<ClaimsIdentity> GenerateIdentity()
        {
            await _cachedIdentityLock.WaitAsync();
            try
            {
                // Check to update cached identity
                if (_cachedIdentity == null || _accessToken.ValidTo <= DateTime.Now)
                {
                    // Validate refresh token expiration
                    if (_refreshToken.ValidTo <= DateTime.Now)
                        throw new Exception("Both the access token and the refresh token have expired");

                    // Load new identity from token endpoint via refresh token
                    var responseMessage =
                        await new RefreshAccessTokenMessage(_parameters, _refreshToken.RawData).ExecuteAsync();
                    await ImportTokenResponse(responseMessage);
                }

                return _cachedIdentity;
            }
            finally
            {
                _cachedIdentityLock.Release();
            }
        }

        protected IEnumerable<Claim> GenerateJwtClaims(JwtSecurityToken accessToken, JwtSecurityToken idToken,
            JwtSecurityToken refreshToken)
        {
            // Add generic claims
            yield return new Claim(Constants.ClaimTypes.AuthenticationType, _parameters.AuthenticationType);
            yield return new Claim(Constants.ClaimTypes.Version, Global.GetVersion());

            // Save the recieved tokens as claims
            if (_parameters.SaveTokensAsClaims)
            {
                if (_idToken != null)
                    yield return new Claim(Constants.ClaimTypes.IdToken, _idToken.RawData);
                if (_accessToken != null)
                    yield return new Claim(Constants.ClaimTypes.AccessToken, _accessToken.RawData);
                if (_refreshToken != null)
                    yield return new Claim(Constants.ClaimTypes.RefreshToken, _refreshToken.RawData);
            }

            // Add OIDC token claims
            var jsonId = _parameters.ClientId;
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