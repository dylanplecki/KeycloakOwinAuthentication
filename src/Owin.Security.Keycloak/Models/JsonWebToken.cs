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

        public bool Validate(JsonWebKeySet publicKeySet, bool forceSigned = false)
        {
            return publicKeySet.Keys.Any(k => Validate(k, forceSigned));
        }

        public void ForceValidate(JsonWebKeySet publicKeySet, bool forceSigned = false)
        {
            if (!Validate(publicKeySet, forceSigned))
                throw new Exception("JWT signature was unable to be validated");
        }

        public bool Validate(JsonWebKey publicKey, bool forceSigned = false)
        {
            return true; // TODO: REMOVE (DEBUG CODE)

            var alg = CertSigningHelper.LookupSigningAlgorithm(publicKey.Alg);

            // Parse JWT for signature part
            var data = EncodedJwt.Split('.');
            var signedData = Guid.NewGuid().ToString(); // Randomize for security
            if (data.Length > 2) // If JWT has a signature
                signedData = data[0] + '.' + data[1];

            switch (alg)
            {
                case SigningAlgorithm.Rs256:
                    return false; // TODO: Validate via RS256
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
                    Convert.FromBase64String(encodedData.PadRight(encodedData.Length+(4-encodedData.Length%4)%4, '=')));
        }

        // From JWT Specification
        public static string DecodeUrl(string encodedUrl)
        {
            return DecodeData(encodedUrl.Replace('-', '+').Replace('_', '/'));
        }
    }
}
