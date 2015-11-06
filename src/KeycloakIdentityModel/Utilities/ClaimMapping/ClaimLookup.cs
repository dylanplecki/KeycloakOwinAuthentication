using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace KeycloakIdentityModel.Utilities.ClaimMapping
{
    internal class ClaimLookup
    {
        public delegate string TransformFunc(JToken token);

        public string ClaimName { get; set; }
        public string JSelectQuery { get; set; }
        public TransformFunc Transformation { get; set; } = token => token.ToString();

        public IEnumerable<Claim> ProcessClaimLookup(JObject jsonObject, string jsonObjectId)
        {
            var token = jsonObject.SelectToken(JSelectQuery.Replace("{gid}", jsonObjectId));
            return token == null ? new List<Claim>() : GenerateClaims(token);
        }

        private IEnumerable<Claim> GenerateClaims(JToken jsonToken)
        {
            switch (jsonToken.Type)
            {
                case JTokenType.Property:
                    foreach (var claim in ((JProperty) jsonToken).Value.SelectMany(GenerateClaims))
                        yield return claim;
                    break;

                case JTokenType.Array:
                    foreach (var claim in ((JArray) jsonToken).SelectMany(GenerateClaims))
                        yield return claim;
                    break;

                case JTokenType.Object:
                    foreach (
                        var claim in
                            ((JObject) jsonToken).Children().SelectMany(GenerateClaims))
                        yield return claim;
                    break;

                default:
                    yield return new Claim(ClaimName, Transformation?.Invoke(jsonToken));
                    break;
            }
        }
    }
}