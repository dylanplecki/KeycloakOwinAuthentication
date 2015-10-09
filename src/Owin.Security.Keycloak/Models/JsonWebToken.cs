using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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
                var header = JObject.Parse(DecodeData(encodedData[0]));
                Algorithm = CertSigningHelper.LookupSigningAlgorithm(header["alg"].ToString());

                // Store JWT properties
                Payload = JObject.Parse(DecodeData(encodedData[1]));
                Signature = (encodedData.Length > 2) ? DecodeUrl(encodedData[2]) : "";
            }
            catch (Exception e)
            {
                throw new Exception("JWebToken: Invalid JWT passed to decode", e);
            }
        }

        public bool Validate(JsonWebKeySet publicKeySet, KeycloakAuthenticationOptions options)
        {
            var uriManager = OidcDataManager.GetCachedContext(options);
            return
                publicKeySet.Keys.Any(
                    k => Validate(k, options.ClientId, uriManager.GetIssuer(), !options.AllowUnsignedTokens));
        }

        public void ForceValidate(JsonWebKeySet publicKeySet, KeycloakAuthenticationOptions options)
        {
            if (!Validate(publicKeySet, options))
                throw new Exception("JWT signature was unable to be validated");
        }

        public bool Validate(JsonWebKeySet publicKeySet, string aud = null, string iss = null, bool forceSigned = false)
        {
            return publicKeySet.Keys.Any(k => Validate(k, aud, iss, forceSigned));
        }

        public void ForceValidate(JsonWebKeySet publicKeySet, string aud = null, string iss = null,
            bool forceSigned = false)
        {
            if (!Validate(publicKeySet, aud, iss, forceSigned))
                throw new Exception("JWT signature was unable to be validated");
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

            return true; // TODO: Remove debug code

            // Parse JWT for signature part
            var data = EncodedJwt.Split('.');
            var signatureData = Guid.NewGuid().ToString(); // Randomize for security
            if (data.Length > 2) // If JWT has a signature
                signatureData = data[0] + '.' + data[1];
            var byteSigData = Encoding.UTF8.GetBytes(signatureData);
            var byteSignature = Encoding.UTF8.GetBytes(Signature);

            switch (alg)
            {
                // TODO: Implement all signing algorithms
                case SigningAlgorithm.Rs256:
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        return rsa.VerifyData(byteSigData, "SHA256", byteSignature);
                    }
                case SigningAlgorithm.Hs256:
                    return false; // TODO: Validate via HS256
                case SigningAlgorithm.None:
                    return !forceSigned;
                default:
                    return false;
            }
        }

        private static string DecodeData(string encodedData)
        {
            return
                Encoding.UTF8.GetString(
                    Convert.FromBase64String(encodedData.PadRight(encodedData.Length + (4 - encodedData.Length%4)%4, '=')));
        }

        // From JWT Specification
        public static string DecodeUrl(string encodedUrl)
        {
            return DecodeData(encodedUrl.Replace('-', '+').Replace('_', '/'));
        }
    }
}
