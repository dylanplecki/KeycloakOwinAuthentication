using System.Collections.Specialized;
using System.Web;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Models
{
    internal class TokenResponse : OidcBaseResponse
    {
        public string AccessToken { get; private set; }
        public string ExpiresIn { get; private set; }
        public string IdToken { get; private set; }
        public string RefreshToken { get; private set; }
        public string TokenType { get; private set; }

        public TokenResponse(string query)
        {
            Init(HttpUtility.ParseQueryString(query));
        }

        public TokenResponse(JObject json)
        {
            var authResult = new NameValueCollection();

            // Convert JSON to NameValueCollection type
            foreach (var item in json)
            {
                authResult.Add(item.Key, item.Value.ToString());
            }

            Init(authResult);
        }

        public TokenResponse(NameValueCollection authResult)
        {
            Init(authResult);
        }

        protected new void Init(NameValueCollection authResult)
        {
            base.Init(authResult);

            AccessToken = authResult.Get(OpenIdConnectParameterNames.AccessToken);
            ExpiresIn = authResult.Get(OpenIdConnectParameterNames.ExpiresIn);
            IdToken = authResult.Get(OpenIdConnectParameterNames.IdToken);
            TokenType = authResult.Get(OpenIdConnectParameterNames.TokenType);
            RefreshToken = authResult.Get("refresh_token");
        }
    }
}
