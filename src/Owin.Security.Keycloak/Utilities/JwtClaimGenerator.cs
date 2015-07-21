using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Utilities
{
    internal static class JwtClaimGenerator
    {
        public static List<Claim> GenerateClaims(JObject json)
        {
            var claims = new List<Claim>();
            var audience = json["aud"];

            foreach (var lookupClaim in JwtClaimMappings)
            {
                var query = string.Format(lookupClaim.JSelectQuery, audience);
                var token = json.SelectToken(query);

                if (token == null) continue;
                if (lookupClaim.IsPluralQuery)
                {
                    claims.AddRange(token.Children().Select(item => new Claim(lookupClaim.ClaimName, item.ToString())));
                }
                else
                {
                    claims.Add(new Claim(lookupClaim.ClaimName, token.ToString()));
                }
            }

            return claims;
        }

        private struct LookupClaim
        {
            public string ClaimName {get; set; }
            public string JSelectQuery { get; set; }
            public bool IsPluralQuery { get; set; }
        }

        private static readonly List<LookupClaim> JwtClaimMappings = new List<LookupClaim>
        {
            new LookupClaim
            {
                ClaimName = ClaimTypes.Name,
                JSelectQuery = "preferred_username"
            },
            new LookupClaim
            {
                ClaimName = ClaimTypes.GivenName,
                JSelectQuery = "given_name"
            },
            new LookupClaim
            {
                ClaimName = ClaimTypes.Surname,
                JSelectQuery = "family_name"
            },
            new LookupClaim
            {
                ClaimName = ClaimTypes.Email,
                JSelectQuery = "email"
            },
            new LookupClaim
            {
                ClaimName = ClaimTypes.Expiration,
                JSelectQuery = "exp"
            },
            new LookupClaim
            {
                ClaimName = ClaimTypes.Role,
                JSelectQuery = "resource_access.{0}.roles",
                IsPluralQuery = true
            }
        };
    }
}
