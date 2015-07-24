using System;
using System.IdentityModel;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak.Models.Messages
{
    internal class RequestAccessTokenMessage : GenericMessage<AuthenticationTicket>
    {
        private AuthorizationResponse AuthResponse { get; }

        public RequestAccessTokenMessage(IOwinRequest request, KeycloakAuthenticationOptions options,
            AuthorizationResponse authResponse)
            : base(request, options)
        {
            if (authResponse == null) throw new ArgumentNullException();
            AuthResponse = authResponse;
        }

        public override async Task<AuthenticationTicket> ExecuteAsync()
        {
            // Validate passed state
            var stateData = StateCache.ReturnState(AuthResponse.State);
            if (stateData == null)
                throw new BadRequestException("Invalid state: Please reattempt the request");

            // Generate claims and create user information
            var tokenResponse = await ExecuteHttpRequestAsync();
            var claims = await JwtClaimGenerator.GenerateClaimsAsync(tokenResponse, Options.SaveTokensAsClaims);
            var identity = new ClaimsIdentity(claims, Options.SignInAsAuthenticationType);
            var properties = stateData[StateCache.PropertyNames.AuthenticationProperties] as AuthenticationProperties ??
                             new AuthenticationProperties();

            return new AuthenticationTicket(identity, properties);
        }

        private async Task<string> ExecuteHttpRequestAsync()
        {
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            var response = await SendHttpPostRequest(uriManager.TokenEndpoint,
                uriManager.BuildAccessTokenEndpointContent(Request.Uri, AuthResponse.Code));
            return await response.Content.ReadAsStringAsync();
        }
    }
}
