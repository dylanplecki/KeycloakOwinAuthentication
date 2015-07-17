using System.Collections.Specialized;
using System.Web;
using Microsoft.IdentityModel.Protocols;

namespace Owin.Security.Keycloak.Models
{
    internal class AuthorizationResponse : OidcBaseResponse
    {
        public string Code { get; private set; }
        public string State { get; private set; }

        public AuthorizationResponse(string query)
        {
            Init(HttpUtility.ParseQueryString(query));
        }

        public AuthorizationResponse(NameValueCollection authResult)
        {
            Init(authResult);
        }

        protected new void Init(NameValueCollection authResult)
        {
            base.Init(authResult);

            Code = authResult.Get(OpenIdConnectParameterNames.Code);
            State = authResult.Get(OpenIdConnectParameterNames.State);
        }
    }
}
