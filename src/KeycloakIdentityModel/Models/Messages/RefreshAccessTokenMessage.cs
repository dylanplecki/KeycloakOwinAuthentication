using System;
using System.Threading.Tasks;
using KeycloakIdentityModel.Models.Configuration;
using KeycloakIdentityModel.Models.Responses;
using KeycloakIdentityModel.Utilities;

namespace KeycloakIdentityModel.Models.Messages
{
    public class RefreshAccessTokenMessage : GenericMessage<TokenResponse>
    {
        public RefreshAccessTokenMessage(IKeycloakParameters options, string refreshToken)
            : base(options)
        {
            if (refreshToken == null) throw new ArgumentNullException();
            RefreshToken = refreshToken;
        }

        private string RefreshToken { get; }

        public override async Task<TokenResponse> ExecuteAsync()
        {
            return new TokenResponse(await ExecuteHttpRequestAsync());
        }

        private async Task<string> ExecuteHttpRequestAsync()
        {
            var uriManager = await OidcDataManager.GetCachedContextAsync(Options);
            var response =
                await
                    SendHttpPostRequest(uriManager.GetTokenEndpoint(),
                        uriManager.BuildRefreshTokenEndpointContent(RefreshToken));
            return await response.Content.ReadAsStringAsync();
        }
    }
}