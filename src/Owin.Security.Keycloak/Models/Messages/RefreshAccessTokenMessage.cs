using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin.Security.Keycloak.Internal;
using Owin.Security.Keycloak.Internal.ClaimMapping;

namespace Owin.Security.Keycloak.Models.Messages
{
    internal class RefreshAccessTokenMessage : GenericMessage<IEnumerable<Claim>>
    {
        public RefreshAccessTokenMessage(IOwinRequest request, KeycloakAuthenticationOptions options,
            string refreshToken)
            : base(request, options)
        {
            if (refreshToken == null) throw new ArgumentNullException();
            RefreshToken = refreshToken;
        }

        private string RefreshToken { get; }

        public override async Task<IEnumerable<Claim>> ExecuteAsync()
        {
            var tokenResponse = await ExecuteHttpRequestAsync(RefreshToken);
            return await ClaimGenerator.GenerateJwtClaimsAsync(tokenResponse, Options);
        }

        private async Task<string> ExecuteHttpRequestAsync(string refreshToken)
        {
            var uriManager = await OidcDataManager.GetCachedContext(Options);
            var response =
                await
                    SendHttpPostRequest(uriManager.GetTokenEndpoint(),
                        uriManager.BuildRefreshTokenEndpointContent(refreshToken));
            return await response.Content.ReadAsStringAsync();
        }
    }
}