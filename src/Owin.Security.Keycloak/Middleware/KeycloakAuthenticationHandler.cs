using System;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Owin.Security.Keycloak.Models;
using Owin.Security.Keycloak.Utilities;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationHandler : AuthenticationHandler<BocAuthenticationOptions>
    {
        private const string CookiePrefix = "boca_authtype_";

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            return await ValidateCookie();
        }

        public override async Task<bool> InvokeAsync()
        {
            // Check for valid callback URI
            if (Request.Uri.GetLeftPart(UriPartial.Path) == GenerateCallbackUri().ToString())
            {
                // Create authorization result from query
                var authResult = new AuthorizationResponse(Request.Uri.Query);

                // Check for errors
                authResult.ThrowIfError();

                // Process response
                return await MakeTokenRequestAsync(authResult.Code, authResult.State);
            }

            return false;
        }

        protected override async Task ApplyResponseGrantAsync()
        {
            // TODO
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            await LoginRedirectAsync();
        }

        #region OIDC Helper Functions

        private async Task<AuthenticationTicket> ValidateCookie()
        {
            var authCookie = Request.Cookies[CookiePrefix + Options.AuthenticationType.ToLower()];

            // Cookie not found
            if (authCookie == null) return null;

            // Load token validation parameters
            var tokenParameters = new TokenValidationParameters(); // TODO: Check parameters

            // Validate JWT and load identity principal
            SecurityToken token;
            var jwtHandler = new JwtSecurityTokenHandler();
            var principal = jwtHandler.ValidateToken(authCookie, tokenParameters, out token);

            // Get primary identity
            var identity = principal.Identity as ClaimsIdentity;
            if (identity == null) return null;

            // Generate authentication properties
            var properties = new AuthenticationProperties(); // TODO: Check properties

            return new AuthenticationTicket(identity, properties);
        }

        private async Task LoginRedirectAsync()
        {
            // Generate login URI
            var returnUri = Request.Uri;
            var uriManager = OidcUriManager.GetCachedContext(Options);
            var loginUrl = uriManager.AuthorizationEndpoint;
            var loginParams = uriManager.BuildAuthorizationEndpointContent(GenerateCallbackUri(), returnUri);

            // Redirect response to login
            Response.Redirect(loginUrl + "?" + await loginParams.ReadAsStringAsync());
        }

        private async Task LogoutRedirectAsync()
        {
            // TODO: Logout

            // Redirect response to post logout URI
            if (Options.PostLogoutRedirectUri != null)
                Response.Redirect(Options.PostLogoutRedirectUri);
        }

        private async Task<bool> MakeTokenRequestAsync(string code, string state)
        {
            // Make HTTP call to token endpoint
            HttpResponseMessage response;
            try
            {
                var client = new HttpClient();
                var uriManager = OidcUriManager.GetCachedContext(Options);
                response =
                    await client.PostAsync(uriManager.TokenEndpoint, uriManager.BuildTokenEndpointContent(code, state));
            }
            catch (Exception exception)
            {
                throw new Exception("Cannot access token endpoint: Check inner exception", exception);
            }

            // Parse response into JSON object and convert to model
            var json = JObject.Parse(await response.Content.ReadAsStringAsync());
            var tokenResponse = new TokenResponse(json);

            // Load token validation parameters
            var tokenParameters = new TokenValidationParameters(); // TODO: Check parameters

            // Validate JWT AuthCode and load identity principal
            SecurityToken token;
            var jwtHandler = new JwtSecurityTokenHandler();
            var principal = jwtHandler.ValidateToken(tokenResponse.AccessToken, tokenParameters, out token);


        }

        private Uri GenerateCallbackUri()
        {
            return new Uri(Request.Uri.GetLeftPart(UriPartial.Authority) + Options.CallbackPath);
        }

        #endregion
    }
}
