using System;
using System.Collections.Specialized;
using Microsoft.IdentityModel.Protocols;

namespace KeycloakIdentityModel.Models.Responses
{
    public abstract class OidcResponse
    {
        public string Error { get; private set; }
        public string ErrorUri { get; private set; }
        public string ErrorDescription { get; private set; }

        protected void InitFromRequest(NameValueCollection authResult)
        {
            Error = authResult.Get(OpenIdConnectParameterNames.Error);
            ErrorUri = authResult.Get(OpenIdConnectParameterNames.ErrorUri);
            ErrorDescription = authResult.Get(OpenIdConnectParameterNames.ErrorDescription);
        }

        public bool IsSuccessfulResponse()
        {
            return Error == null;
        }

        public void ThrowIfError()
        {
            if (!IsSuccessfulResponse())
            {
                throw new Exception(
                    $"OIDC Error in AuthorizationResult [{Error}]: {ErrorDescription ?? "NO DESCRIPTION"} (URI: '{ErrorUri ?? "N/A"}')");
            }
        }
    }
}