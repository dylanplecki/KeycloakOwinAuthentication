using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Models.Responses
{
    internal class TokenResponse : OidcResponse
    {
        public TokenResponse(string encodedJson)
            : this(JObject.Parse(encodedJson))
        {
        }

        public TokenResponse(JObject json)
        {
            var authResult = new NameValueCollection();

            // Convert JSON to NameValueCollection type
            foreach (var item in json)
                authResult.Add(item.Key, item.Value.ToString());

            InitFromRequest(authResult);
        }

        public TokenResponse(JwtSecurityToken accessToken, JwtSecurityToken idToken = null,
            JwtSecurityToken refreshToken = null)
        {
            IdToken = idToken;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }

        public string ExpiresIn { get; private set; }
        public string TokenType { get; private set; }

        public JwtSecurityToken IdToken { get; private set; }
        public JwtSecurityToken AccessToken { get; private set; }
        public JwtSecurityToken RefreshToken { get; private set; }

        protected new void InitFromRequest(NameValueCollection authResult)
        {
            base.InitFromRequest(authResult);

            ExpiresIn = authResult.Get(OpenIdConnectParameterNames.ExpiresIn);
            TokenType = authResult.Get(OpenIdConnectParameterNames.TokenType);

            IdToken = new JwtSecurityToken(authResult.Get(OpenIdConnectParameterNames.IdToken));
            AccessToken = new JwtSecurityToken(authResult.Get(OpenIdConnectParameterNames.AccessToken));
            RefreshToken = new JwtSecurityToken(authResult.Get(Constants.OpenIdConnectParameterNames.RefreshToken));
        }
    }
}