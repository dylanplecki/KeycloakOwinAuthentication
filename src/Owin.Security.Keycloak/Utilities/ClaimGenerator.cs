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
    internal static class ClaimGenerator
    {
        public static Task<IEnumerable<Claim>> GenerateJwtClaimsAsync(string content, IKeycloakOptions options)
        {
            // Run code on background thread
            return Task.Run(() =>
            {
                // TODO: Provide sanity validation below
                var claims = new List<Claim>();
                var json = JObject.Parse(content);

                if (options.SaveTokensAsClaims)
                {
                    ProcessClaimMappings(claims, json, json["session-state"].ToString(), JwtTokenMappings);
                }

                var accessToken = json[Constants.ClaimTypes.AccessToken];
                var encodedData = accessToken.ToString().Split('.')[1];
                encodedData = encodedData.PadRight(encodedData.Length + (4 - encodedData.Length%4)%4, '=');
                var tokenPayload = Encoding.UTF8.GetString(Convert.FromBase64String(encodedData));
                var payloadJson = JObject.Parse(tokenPayload);

                ProcessClaimMappings(claims, payloadJson, payloadJson["aud"].ToString(), JwtClaimMappings);
                claims.Add(new Claim(Constants.ClaimTypes.KeycloakOptions, options.Serialize()));

                return (IEnumerable<Claim>) claims;
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
                ClaimName = Constants.ClaimTypes.AccessToken,
                JSelectQuery = "access_token"
            },
            new LookupClaim
            {
                ClaimName = Constants.ClaimTypes.IdToken,
                JSelectQuery = "id_token"
            },
            new LookupClaim
            {
                ClaimName = Constants.ClaimTypes.RefreshToken,
                JSelectQuery = "refresh_token"
            },
            new LookupClaim
            {
                ClaimName = Constants.ClaimTypes.AccessTokenExpiration,
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
                ClaimName = Constants.ClaimTypes.RefreshTokenExpiration,
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
