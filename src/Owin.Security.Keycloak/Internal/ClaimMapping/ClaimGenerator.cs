using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Internal.ClaimMapping
{
    internal static class ClaimGenerator
    {
        public static Task<IEnumerable<Claim>> GenerateJwtClaimsAsync(string content,
            KeycloakAuthenticationOptions options)
        {
            // Run code on background thread
            return Task.Run(() =>
            {
                // TODO: Provide sanity validation below
                var claims = new List<Claim>();
                var json = JObject.Parse(content);

                if (options.SaveTokensAsClaims)
                {
                    ProcessClaimMappings(claims, json, json["session-state"].ToString(), ClaimMappings.JwtTokenMappings);
                }

                ProcessOidcToken(claims, json[Constants.ClaimTypes.AccessToken], ClaimMappings.AccessTokenMappings);
                ProcessOidcToken(claims, json[Constants.ClaimTypes.IdToken], ClaimMappings.IdTokenMappings);

                // Add generic claims
                claims.Add(new Claim(Constants.ClaimTypes.AuthenticationType, options.AuthenticationType));
                claims.Add(new Claim(Constants.ClaimTypes.Version, Global.GetVersion()));

                return (IEnumerable<Claim>) claims;
            });
        }

        private static void ProcessOidcToken(List<Claim> claims, JToken token, IEnumerable<ClaimLookup> claimMappings)
        {
            var encodedData = token.ToString().Split('.')[1];
            encodedData = encodedData.PadRight(encodedData.Length + (4 - encodedData.Length%4)%4, '=');
            var tokenPayload = Encoding.UTF8.GetString(Convert.FromBase64String(encodedData));
            var payloadJson = JObject.Parse(tokenPayload);

            ProcessClaimMappings(claims, payloadJson, payloadJson["aud"].ToString(), claimMappings);
        }

        private static void ProcessClaimMappings(List<Claim> claims, JToken json, string jsonId,
            IEnumerable<ClaimLookup> claimMappings)
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
    }
}