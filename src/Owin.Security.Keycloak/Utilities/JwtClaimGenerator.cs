using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Utilities
{
    internal static class JwtClaimGenerator
    {
        public static class TokenTypes
        {
            public const string IdToken = "id_token";
            public const string AccessToken = "access_token";
            public const string RefreshToken = "refresh_token";

            public const string AccessTokenExpiration = "access_token_expiration";
            public const string RefreshTokenExpiration = "refresh_token_expiration";
        }

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

                var accessToken = json[TokenTypes.AccessToken];
                var encodedData = accessToken.ToString().Split('.')[1];
                encodedData = encodedData.PadRight(encodedData.Length + (4 - encodedData.Length%4)%4, '=');
                var tokenPayload = Encoding.UTF8.GetString(Convert.FromBase64String(encodedData));
                var payloadJson = JObject.Parse(tokenPayload);

                ProcessClaimMappings(claims, payloadJson, payloadJson["aud"].ToString(), JwtClaimMappings);

                return claims;
            });
        }

        private static void ProcessClaimMappings(List<Claim> claims, JToken json, string jsonId,
            IEnumerable<LookupClaim> claimMappings)
        {
            foreach (var lookupClaim in claimMappings)
            {
                var query = string.Format(lookupClaim.JSelectQuery, jsonId);
                var token = json.SelectToken(query);
                if (token == null) continue;

                if (lookupClaim.IsPluralQuery)
                {
                    claims.AddRange(
                        token.Children()
                            .Select(
                                item =>
                                    new Claim(lookupClaim.ClaimName, lookupClaim.Transformation?.Invoke(item))));
                }
                else
                {
                    claims.Add(new Claim(lookupClaim.ClaimName, lookupClaim.Transformation?.Invoke(token)));
                }
            }
        }

        private class LookupClaim
        {
            public delegate string TransformFunc(JToken token);

            public string ClaimName { get; set; }
            public string JSelectQuery { get; set; }
            public bool IsPluralQuery { get; set; }
            public TransformFunc Transformation { get; set; } = token => token.ToString();
        }

        private static IEnumerable<LookupClaim> JwtClaimMappings { get; } = new List<LookupClaim>
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
                ClaimName = ClaimTypes.Role,
                JSelectQuery = "resource_access.{0}.roles",
                IsPluralQuery = true
            }
        };

        private static IEnumerable<LookupClaim> JwtTokenMappings { get; } = new List<LookupClaim>
        {
            new LookupClaim
            {
                ClaimName = TokenTypes.AccessToken,
                JSelectQuery = TokenTypes.AccessToken
            },
            new LookupClaim
            {
                ClaimName = TokenTypes.IdToken,
                JSelectQuery = TokenTypes.IdToken
            },
            new LookupClaim
            {
                ClaimName = TokenTypes.RefreshToken,
                JSelectQuery = TokenTypes.RefreshToken
            },
            new LookupClaim
            {
                ClaimName = TokenTypes.AccessTokenExpiration,
                JSelectQuery = "expires_in",
                Transformation = delegate(JToken token)
                {
                    var expiresInSec = (token.Value<double?>() ?? 1) - 1;
                    var dateTime = DateTime.Now.AddSeconds(expiresInSec);
                    return dateTime.ToString(CultureInfo.InvariantCulture);
                }
            },
            new LookupClaim
            {
                ClaimName = TokenTypes.RefreshTokenExpiration,
                JSelectQuery = "refresh_expires_in",
                Transformation = delegate(JToken token)
                {
                    var expiresInSec = (token.Value<double?>() ?? 1) - 1;
                    var dateTime = DateTime.Now.AddSeconds(expiresInSec);
                    return dateTime.ToString(CultureInfo.InvariantCulture);
                }
            }
        };
    }
}
