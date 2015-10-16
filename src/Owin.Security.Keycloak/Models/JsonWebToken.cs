using System;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;
using Owin.Security.Keycloak.Internal;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak.Models
{
    internal class JsonWebToken
    {
        public SigningAlgorithm Algorithm { get; private set; }
        public JObject Payload { get; }
        public string Signature { get; }
        public string EncodedJwt { get; }

        public JsonWebToken(string encodedJwt)
        {
            EncodedJwt = encodedJwt;

            try
            {
                var encodedData = encodedJwt.Split('.');
                if (encodedData.Length < 2)
                    throw new Exception("JWebToken: Invalid JWT length");

                // Parse header
                var header = JObject.Parse(CertSigningHelper.DecodeBase64Data(encodedData[0]));
                Algorithm = CertSigningHelper.LookupSigningAlgorithm(header["alg"].ToString());

                // Store JWT properties
                Payload = JObject.Parse(CertSigningHelper.DecodeBase64Data(encodedData[1]));
                Signature = (encodedData.Length > 2) ? CertSigningHelper.DecodeBase64UrlData(encodedData[2]) : "";
            }
            catch (Exception e)
            {
                throw new Exception("JWebToken: Invalid JWT passed to decode", e);
            }
        }

        public async Task<bool> RemoteValidateKeycloakAsync(KeycloakAuthenticationOptions options)
        {
            // This should really only be used on access tokens...
            var uriManager = OidcDataManager.GetCachedContext(options);
            var uri = new Uri(uriManager.TokenValidationEndpoint, "?access_token=" + EncodedJwt);
            try
            {
                var client = new HttpClient();
                var response = await client.GetAsync(uri);
                return response.IsSuccessStatusCode;
            }
            catch (Exception)
            {
                // TODO: Some kind of exception logging
                return false;
            }
        }

        public async Task ForceRemoteValidateKeycloakAsync(KeycloakAuthenticationOptions options)
        {
            if (!await RemoteValidateKeycloakAsync(options)) ThrowJwtInvalid();
        }

        public void ForceValidateKeycloak(JsonWebKeySet publicKeySet, KeycloakAuthenticationOptions options)
        {
            if (!ValidateKeycloak(publicKeySet, options)) ThrowJwtInvalid();
        }

        public bool ValidateKeycloak(JsonWebKeySet publicKeySet, KeycloakAuthenticationOptions options)
        {
            var uriManager = OidcDataManager.GetCachedContext(options);
            return Validate(publicKeySet, options.ClientId, uriManager.GetIssuer(), !options.AllowUnsignedTokens);
        }

        public void ForceValidate(JsonWebKeySet publicKeySet, string audience = null, string issuer = null,
            bool forceSigned = false)
        {
            if (!Validate(publicKeySet, audience, issuer, forceSigned)) ThrowJwtInvalid();
        }

        public bool Validate(JsonWebKeySet publicKeySet, string audience = null, string issuer = null, bool forceSigned = false)
        {
            SecurityToken secToken;
            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenValidationParams = new TokenValidationParameters
            {
                ValidIssuer = issuer ?? "",
                ValidAudience = audience ?? "",
                ValidateIssuer = issuer != null,
                ValidateAudience = audience != null,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                RequireSignedTokens = forceSigned,
                IssuerSigningTokens = publicKeySet.GetSigningTokens(),
                ClockSkew = new TimeSpan(0, 0, 5) // 5 seconds
            };

            var test = tokenHandler.ValidateToken(EncodedJwt, tokenValidationParams, out secToken);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThrowJwtInvalid()
        {
            throw new Exception("JWT signature was unable to be validated");
        }
    }
}