using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak.Models.Messages
{
    internal class RefreshAccessTokenMessage : GenericMessage<List<Claim>>
    {
        private string RefreshToken { get; }

        public RefreshAccessTokenMessage(IOwinRequest request, KeycloakAuthenticationOptions options,
            string refreshToken)
            : base(request, options)
        {
            if (refreshToken == null) throw new ArgumentNullException();
            RefreshToken = refreshToken;
        }

        public override async Task<List<Claim>> ExecuteAsync()
        {
            var tokenResponse = await ExecuteHttpRequestAsync(RefreshToken);
            return await JwtClaimGenerator.GenerateClaimsAsync(tokenResponse, Options.SaveTokensAsClaims);
        }

        private async Task<string> ExecuteHttpRequestAsync(string refreshToken)
        {
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            var response =
                await
                    SendHttpPostRequest(uriManager.TokenEndpoint,
                        uriManager.BuildRefreshTokenEndpointContent(refreshToken));
            return await response.Content.ReadAsStringAsync();
        }
    }
}
