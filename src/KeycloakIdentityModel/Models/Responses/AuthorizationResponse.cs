using System;
using System.Collections.Specialized;
using System.Web;
using Microsoft.IdentityModel.Protocols;

namespace KeycloakIdentityModel.Models.Responses
{
    public class AuthorizationResponse : OidcResponse
    {
        public AuthorizationResponse(string query)
        {
            InitFromRequest(HttpUtility.ParseQueryString(query));

            if (!Validate())
            {
                throw new ArgumentException("Invalid query string used to instantiate an AuthorizationResponse");
            }
        }

        public string Code { get; private set; }
        public string State { get; private set; }

        protected new void InitFromRequest(NameValueCollection authResult)
        {
            base.InitFromRequest(authResult);

            Code = authResult.Get(OpenIdConnectParameterNames.Code);
            State = authResult.Get(OpenIdConnectParameterNames.State);
        }

        public bool Validate()
        {
            return !string.IsNullOrWhiteSpace(Code) && !string.IsNullOrWhiteSpace(State);
        }
    }
}