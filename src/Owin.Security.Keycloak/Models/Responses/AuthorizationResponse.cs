using System;
using System.Collections.Specialized;
using System.Web;
using Microsoft.IdentityModel.Protocols;

namespace Owin.Security.Keycloak.Models.Responses
{
    internal class AuthorizationResponse : OidcResponse
    {
        public AuthorizationResponse(string query)
        {
            Init(HttpUtility.ParseQueryString(query));

            if (!Validate())
            {
                throw new ArgumentException("Invalid query string used to instantiate an AuthorizationResponse");
            }
        }

        public AuthorizationResponse(NameValueCollection authResult)
        {
            Init(authResult);
        }

        public string Code { get; private set; }
        public string State { get; private set; }

        public bool Validate()
        {
            return !string.IsNullOrWhiteSpace(Code) && !string.IsNullOrWhiteSpace(State);
        }
    }
}