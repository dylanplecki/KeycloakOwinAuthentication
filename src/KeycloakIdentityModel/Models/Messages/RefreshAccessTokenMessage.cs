using System;
using System.Security.Claims;
using System.Threading.Tasks;
using KeycloakIdentityModel.Models.Configuration;
using KeycloakIdentityModel.Utilities;

namespace KeycloakIdentityModel.Models.Messages
{
    public class RefreshAccessTokenMessage : GenericMessage<ClaimsIdentity>
    {
        public RefreshAccessTokenMessage(Uri baseUri, IKeycloakParameters options,
            string refreshToken)
            : base(baseUri, options)
        {
            if (refreshToken == null) throw new ArgumentNullException();
            RefreshToken = refreshToken;
        }

        private string RefreshToken { get; }

        public override async Task<ClaimsIdentity> ExecuteAsync()
        {
            var newKcIdentity = new KeycloakIdentity(await ExecuteHttpRequestAsync(RefreshToken));
            return await newKcIdentity.ValidateIdentity(Options);
        }

        private async Task<string> ExecuteHttpRequestAsync(string refreshToken)
        {
            var uriManager = OidcDataManager.GetCachedContext(Options);
            var response =
                await
                    SendHttpPostRequest(uriManager.GetTokenEndpoint(),
                        uriManager.BuildRefreshTokenEndpointContent(refreshToken));
            return await response.Content.ReadAsStringAsync();
        }
    }
}