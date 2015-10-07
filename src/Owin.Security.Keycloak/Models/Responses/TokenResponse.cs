using System.Collections.Specialized;
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

            Init(authResult);
        }

        public TokenResponse(NameValueCollection authResult)
        {
            Init(authResult);
        }

        public string AccessToken { get; private set; }
        public string ExpiresIn { get; private set; }
        public string IdToken { get; private set; }
        public string RefreshToken { get; private set; }
        public string TokenType { get; private set; }

        protected new void Init(NameValueCollection authResult)
        {
            base.Init(authResult);

            AccessToken = authResult.Get(OpenIdConnectParameterNames.AccessToken);
            ExpiresIn = authResult.Get(OpenIdConnectParameterNames.ExpiresIn);
            IdToken = authResult.Get(OpenIdConnectParameterNames.IdToken);
            TokenType = authResult.Get(OpenIdConnectParameterNames.TokenType);
            RefreshToken = authResult.Get(Constants.OpenIdConnectParameterNames.RefreshToken);
        }
    }
}