using System;
using System.Linq;
using System.Text;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak.Models
{
    internal class JsonWebToken
    {
        public SigningAlgorithm Algorithm { get; private set; }
        public JObject Payload { get; private set; }
        public string Signature { get; private set; }
        public string EncodedJwt { get; private set; }

        // TODO: Optimize this out via encoding mechanism
        private readonly string _jwtHeaderPayload;

        public JsonWebToken(string encodedJwt)
        {
            EncodedJwt = encodedJwt;

            try
            {
                var encodedData = encodedJwt.Split('.');
                if (encodedData.Length < 2)
                    throw new Exception("JWebToken: Invalid JWT length");

                // Save header + payload for verification
                _jwtHeaderPayload = encodedData[0] + '.' + encodedData[1];

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

        public bool Validate(JsonWebKeySet publicKeySet)
        {
            return publicKeySet.Keys.Any(Validate);
        }

        public bool Validate(JsonWebKey publicKey)
        {
            // TODO: Finish validation function
            return false;
        }

        private static string DecodeData(string encodedData)
        {
            return
                Encoding.UTF8.GetString(
                    Convert.FromBase64String(encodedData.PadRight(encodedData.Length+(4-encodedData.Length%4)%4, '=')));
        }

        // From JWT Specification
        public static string DecodeUrl(string encodedUrl)
        {
            return DecodeData(encodedUrl.Replace('-', '+').Replace('_', '/'));
        }
    }
}
