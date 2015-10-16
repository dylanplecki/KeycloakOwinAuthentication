using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
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

        public ClaimsIdentity ValidateIdentity(KeycloakAuthenticationOptions options, string authenticationType = null)
        {
            var uriManager = OidcDataManager.GetCachedContext(options);

            // Prepare JWT validation parameters
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = uriManager.GetIssuer(),
                ClockSkew = TimeSpan.FromSeconds(5), // 5 seconds
                ValidAudiences = new List<string> {"null", options.ClientId},
                IssuerSigningTokens = uriManager.GetJsonWebKeys().GetSigningTokens(),
                AuthenticationType = authenticationType ?? options.SignInAsAuthenticationType
            };

            // Validate JWTs provided
            SecurityToken securityToken;
            tokenHandler.ValidateToken(_keycloakToken.RefreshToken.RawData,
                tokenValidationParameters, out securityToken);
            //if (_keycloakToken.IdToken != null &&
            //    tokenHandler.ValidateToken(_keycloakToken.IdToken.RawData, tokenValidationParameters))
            //    throw new SecurityTokenException("Invalid OpenID Connect ID-JWT");

            // Generate claims principle from validated access token
            var claimsPrinciple = tokenHandler.ValidateToken(_keycloakToken.AccessToken.RawData,
                tokenValidationParameters, out securityToken);
            var identity = claimsPrinciple.Identities.FirstOrDefault();
            if (identity == null) throw new SecurityTokenException("Invalid identity returned from JWT");
            return identity;

            //_keycloakToken.IdToken?.ForceValidateKeycloak(signingKeys, options);
            //_keycloakToken.RefreshToken?.ForceValidateKeycloak(signingKeys, options);

            //if (options.UseRemoteTokenValidation && _keycloakToken.AccessToken != null)
            //    await _keycloakToken.AccessToken.ForceRemoteValidateKeycloakAsync(options);
            //else
            //    _keycloakToken.AccessToken?.ForceValidateKeycloak(signingKeys, options);

            //// Create the new claims identity
            //return new ClaimsIdentity(GenerateJwtClaims(options),
            //    authenticationType ?? options.SignInAsAuthenticationType);
        }

        //public IEnumerable<Claim> GenerateJwtClaims(KeycloakAuthenticationOptions options)
        //{
        //    // Add generic claims
        //    yield return new Claim(Constants.ClaimTypes.AuthenticationType, options.AuthenticationType);
        //    yield return new Claim(Constants.ClaimTypes.Version, Global.GetVersion());

        //    // Save the recieved tokens as claims
        //    if (options.SaveTokensAsClaims)
        //    {
        //        if (_keycloakToken.IdToken != null)
        //            yield return new Claim(Constants.ClaimTypes.IdToken, _keycloakToken.IdToken.RawData);
        //        if (_keycloakToken.AccessToken != null)
        //            yield return new Claim(Constants.ClaimTypes.AccessToken, _keycloakToken.AccessToken.RawData);
        //        if (_keycloakToken.RefreshToken != null)
        //            yield return new Claim(Constants.ClaimTypes.RefreshToken, _keycloakToken.RefreshToken.RawData);
        //    }

        //    // Add OIDC token claims
        //    var jsonId = options.ClientId;
        //    if (_keycloakToken.IdToken != null)
        //        foreach (var claim in ProcessOidcToken(_keycloakToken.IdToken, ClaimMappings.IdTokenMappings, jsonId))
        //            yield return claim;
        //    if (_keycloakToken.AccessToken != null)
        //        foreach (
        //            var claim in ProcessOidcToken(_keycloakToken.AccessToken, ClaimMappings.AccessTokenMappings, jsonId)
        //            )
        //            yield return claim;
        //    if (_keycloakToken.RefreshToken != null)
        //        foreach (
        //            var claim in
        //                ProcessOidcToken(_keycloakToken.RefreshToken, ClaimMappings.RefreshTokenMappings, jsonId))
        //            yield return claim;
        //}

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        //private static IEnumerable<Claim> ProcessOidcToken(JwtSecurityToken webToken,
        //    IEnumerable<ClaimLookup> claimMappings, string jsonId)
        //{
        //    // Process claim mappings
        //    return claimMappings.SelectMany(lookupClaim => lookupClaim.ProcessClaimLookup(webToken.Payload, jsonId));
        //}
    }
}
