using System.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak
{
    internal static class JwtSecurityTokenExtension
    {
        public static JObject GetPayloadJObject(this JwtSecurityToken token)
        {
            // TODO: Optimize? Reduce code duplication
            return JObject.Parse(Base64UrlEncoder.Decode(token.RawPayload));
        }
    }
}