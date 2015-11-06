using System.Collections.Specialized;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json.Linq;

namespace KeycloakIdentityModel.Models.Responses
{
    public class TokenResponse : OidcResponse
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

        public TokenResponse(string accessToken, string idToken, string refreshToken)
        {
            IdToken = idToken;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }

        public string ExpiresIn { get; private set; }
        public string TokenType { get; private set; }

        public string IdToken { get; private set; }
        public string AccessToken { get; private set; }
        public string RefreshToken { get; private set; }

        protected new void InitFromRequest(NameValueCollection authResult)
        {
            base.InitFromRequest(authResult);

            ExpiresIn = authResult.Get(OpenIdConnectParameterNames.ExpiresIn);
            TokenType = authResult.Get(OpenIdConnectParameterNames.TokenType);

            IdToken = authResult.Get(OpenIdConnectParameterNames.IdToken);
            AccessToken = authResult.Get(OpenIdConnectParameterNames.AccessToken);
            RefreshToken = authResult.Get(Constants.OpenIdConnectParameterNames.RefreshToken);
        }
    }
}