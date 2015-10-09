using System;
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
        public bool RequirePropertyId { get; set; } = false;
        public TransformFunc Transformation { get; set; } = token => token.ToString();

        public IEnumerable<Claim> ProcessClaimLookup(JObject jsonObject, string jsonObjectId)
        {
            var token = jsonObject.SelectToken(JSelectQuery);
            return token == null ? new List<Claim>() : GenerateClaims(token, jsonObjectId);
        }

        private IEnumerable<Claim> GenerateClaims(JToken jsonToken, string jsonTokenId)
        {
            if (jsonToken.Type == JTokenType.Property)
            {
                if (RequirePropertyId &&
                    !string.Equals(((JProperty) jsonToken).Name, jsonTokenId, StringComparison.CurrentCultureIgnoreCase))
                    yield break;
                var jsonValueToken = ((JProperty) jsonToken).Value;

                switch (jsonValueToken.Type)
                {
                    case JTokenType.Array:
                        foreach (var claim in ((JArray) jsonValueToken).SelectMany(t => GenerateClaims(t, jsonTokenId)))
                            yield return claim;
                        break;
                    case JTokenType.Object:
                        foreach (
                            var claim in
                                ((JObject) jsonValueToken).Children().SelectMany(t => GenerateClaims(t, jsonTokenId)))
                            yield return claim;
                        break;
                    default:
                        yield return new Claim(ClaimName, Transformation?.Invoke(jsonValueToken));
                        break;
                }
            }
            else
            {
                yield return new Claim(ClaimName, Transformation?.Invoke(jsonToken));
            }
        }
    }
}