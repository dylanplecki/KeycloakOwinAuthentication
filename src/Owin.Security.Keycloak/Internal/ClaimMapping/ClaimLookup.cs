using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Internal.ClaimMapping
{
    internal class ClaimLookup
    {
        public delegate string TransformFunc(JToken token);

        public string ClaimName { get; set; }
        public string JSelectQuery { get; set; }
        public TransformFunc Transformation { get; set; } = token => token.ToString();

        public IEnumerable<Claim> ProcessClaimLookup(JObject jsonObject)
        {
            var token = jsonObject.SelectToken(JSelectQuery);
            return token == null ? new List<Claim>() : GenerateClaims(token);
        }

        private IEnumerable<Claim> GenerateClaims(JToken jsonToken)
        {
            switch (jsonToken.Type)
            {
                case JTokenType.Array:
                    foreach (var returnToken in ((JArray) jsonToken).SelectMany(GenerateClaims))
                        yield return returnToken;
                    break;
                case JTokenType.Object:
                    foreach (var returnToken in ((JObject) jsonToken).Children().SelectMany(GenerateClaims))
                        yield return returnToken;
                    break;
                default:
                    yield return new Claim(ClaimName, Transformation?.Invoke(jsonToken));
                    break;
            }
        }
    }
}