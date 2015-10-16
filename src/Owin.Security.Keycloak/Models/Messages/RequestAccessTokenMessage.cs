using System;
using System.IdentityModel;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Keycloak.Internal;
using Owin.Security.Keycloak.Models.Responses;

namespace Owin.Security.Keycloak.Models.Messages
{
    internal class RequestAccessTokenMessage : GenericMessage<AuthenticationTicket>
    {
        public RequestAccessTokenMessage(IOwinRequest request, KeycloakAuthenticationOptions options,
            AuthorizationResponse authResponse)
            : base(request, options)
        {
            if (authResponse == null) throw new ArgumentNullException();
            AuthResponse = authResponse;
        }

        private AuthorizationResponse AuthResponse { get; }

        public override async Task<AuthenticationTicket> ExecuteAsync()
        {
            // Validate passed state
            var stateData = Global.StateCache.ReturnState(AuthResponse.State);
            if (stateData == null)
                throw new BadRequestException("Invalid state: Please reattempt the request");

            // Generate claims and create user information & authentication ticket
            var kcIdentity = new KeycloakIdentity(await ExecuteHttpRequestAsync());
            var properties = stateData[Constants.CacheTypes.AuthenticationProperties] as AuthenticationProperties ??
                             new AuthenticationProperties();
            return new AuthenticationTicket(await kcIdentity.ValidateIdentity(Options), properties);
        }

        private async Task<string> ExecuteHttpRequestAsync()
        {
            var uriManager = OidcDataManager.GetCachedContext(Options);
            var response = await SendHttpPostRequest(uriManager.GetTokenEndpoint(),
                uriManager.BuildAccessTokenEndpointContent(Request.Uri, AuthResponse.Code));
            return await response.Content.ReadAsStringAsync();
        }
    }
}