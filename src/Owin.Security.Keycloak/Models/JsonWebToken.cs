using System;
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

        public bool ValidateKeycloak(JsonWebKeySet publicKeySet, KeycloakAuthenticationOptions options)
        {
            var uriManager = OidcDataManager.GetCachedContext(options);
            return
                publicKeySet.Keys.Any(
                    k => Validate(k, options.ClientId, uriManager.GetIssuer(), !options.AllowUnsignedTokens));
        }

        public void ForceValidateKeycloak(JsonWebKeySet publicKeySet, KeycloakAuthenticationOptions options)
        {
            if (!ValidateKeycloak(publicKeySet, options)) ThrowJwtInvalid();
        }

        public bool Validate(JsonWebKeySet publicKeySet, string aud = null, string iss = null, bool forceSigned = false)
        {
            return publicKeySet.Keys.Any(k => Validate(k, aud, iss, forceSigned));
        }

        public void ForceValidate(JsonWebKeySet publicKeySet, string aud = null, string iss = null,
            bool forceSigned = false)
        {
            if (!Validate(publicKeySet, aud, iss, forceSigned)) ThrowJwtInvalid();
        }

        public bool Validate(JsonWebKey publicKey, string aud = null, string iss = null, bool forceSigned = false)
        {
            var alg = CertSigningHelper.LookupSigningAlgorithm(publicKey.Alg);

            // Check for basic structure compliance
            // TODO: Convert in-line constants to constants.cs
            double dExp;
            JToken jAud, jIss, jExp;
            if ((aud != null && Payload.TryGetValue("aud", out jAud) && jAud.Type != JTokenType.Null &&
                 aud != jAud.ToString()) |
                (iss != null && Payload.TryGetValue("iss", out jIss) && jIss.Type != JTokenType.Null &&
                 iss != jIss.ToString()) |
                (Payload.TryGetValue("exp", out jExp) && double.TryParse(jExp.ToString(), out dExp) &&
                 dExp.ToDateTime() <= DateTime.Now))
            {
                return false;
            }

            if (alg == SigningAlgorithm.None) return !forceSigned;

            // Parse JWT for signature part
            var data = EncodedJwt.Split('.');
            var signatureData = Guid.NewGuid().ToString(); // Randomize for security
            if (data.Length > 2) // If JWT has a signature
                signatureData = data[0] + '.' + data[1];
            var byteSigData = Encoding.UTF8.GetBytes(signatureData);
            var byteSignature = Encoding.UTF8.GetBytes(Signature);

            return publicKey.ValidateData(byteSigData, byteSignature, alg);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ThrowJwtInvalid()
        {
            throw new Exception("JWT signature was unable to be validated");
        }
    }
}