using System;
using System.Collections.Specialized;
using Microsoft.IdentityModel.Protocols;

namespace Owin.Security.Keycloak.Models.Responses
{
    internal abstract class OidcResponse
    {
        public string Error { get; private set; }
        public string ErrorUri { get; private set; }
        public string ErrorDescription { get; private set; }

        protected void Init(NameValueCollection authResult)
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