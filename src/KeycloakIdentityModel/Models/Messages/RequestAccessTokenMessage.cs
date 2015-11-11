using System;
using System.Security.Claims;
using System.Threading.Tasks;
using KeycloakIdentityModel.Models.Configuration;
using KeycloakIdentityModel.Models.Responses;
using KeycloakIdentityModel.Utilities;

namespace KeycloakIdentityModel.Models.Messages
{
    public class RequestAccessTokenMessage : GenericMessage<ClaimsIdentity>
    {
        public RequestAccessTokenMessage(Uri baseUri, IKeycloakParameters options,
            AuthorizationResponse authResponse)
            : base(baseUri, options)
        {
            if (authResponse == null) throw new ArgumentNullException();
            AuthResponse = authResponse;
        }

        private AuthorizationResponse AuthResponse { get; }

        public override async Task<ClaimsIdentity> ExecuteAsync()
        {
            // Generate claims and create user information & identity
            var kcIdentity = new KeycloakIdentity(await ExecuteHttpRequestAsync());
            return await kcIdentity.ValidateIdentity(Options);
        }

        private async Task<string> ExecuteHttpRequestAsync()
        {
            var uriManager = OidcDataManager.GetCachedContext(Options);
            var response = await SendHttpPostRequest(uriManager.GetTokenEndpoint(),
                uriManager.BuildAccessTokenEndpointContent(BaseUri, AuthResponse.Code));
            return await response.Content.ReadAsStringAsync();
        }
    }
}