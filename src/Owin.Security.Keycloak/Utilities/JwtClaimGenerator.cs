using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Utilities
{
    internal static class JwtClaimGenerator
    {
        public static Task<List<Claim>> GenerateClaimsAsync(string content, bool saveTokens = false)
        {
            // Run code on background thread
            return Task.Run(() =>
            {
                // TODO: Provide sanity validation below
                var claims = new List<Claim>();
                var json = JObject.Parse(content);

                if (saveTokens)
                {
                    ProcessClaimMappings(claims, json, json["session-state"].ToString(), JwtTokenMappings);
                }

                var accessToken = json["access_token"];
                var encodedData = accessToken.ToString().Split('.')[1];
                encodedData = encodedData.PadRight(encodedData.Length + (4 - encodedData.Length%4)%4, '=');
                var tokenPayload = Encoding.UTF8.GetString(Convert.FromBase64String(encodedData));
                var payloadJson = JObject.Parse(tokenPayload);

                ProcessClaimMappings(claims, payloadJson, payloadJson["aud"].ToString(), JwtClaimMappings);

                return claims;
            });
        }

        private static void ProcessClaimMappings(List<Claim> claims, JToken json, string jsonId,
            List<LookupClaim> claimMappings)
        {
            foreach (var lookupClaim in JwtClaimMappings)
            {
                var query = string.Format(lookupClaim.JSelectQuery, jsonId);
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
        }

        private struct LookupClaim
        {
            public string ClaimName { get; set; }
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

        private static readonly List<LookupClaim> JwtTokenMappings = new List<LookupClaim>
        {
            new LookupClaim
            {
                ClaimName = "access_token",
                JSelectQuery = "access_token"
            },
            new LookupClaim
            {
                ClaimName = "id_token",
                JSelectQuery = "id_token"
            },
            new LookupClaim
            {
                ClaimName = "refresh_token",
                JSelectQuery = "refresh_token"
            },
            new LookupClaim
            {
                ClaimName = "expires_in",
                JSelectQuery = "expires_in"
            },
            new LookupClaim
            {
                ClaimName = "refresh_expires_in",
                JSelectQuery = "refresh_expires_in"
            }
        };
    }
}
