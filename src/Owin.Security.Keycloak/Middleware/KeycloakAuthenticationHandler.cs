using System;
using System.IdentityModel.Tokens;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using Owin.Security.Keycloak.Models;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationHandler : AuthenticationHandler<KeycloakAuthenticationOptions>
    {
        private const string CookiePrefix = "oidc_authtype_";

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            return await ValidateCookie();
        }

        public override async Task<bool> InvokeAsync()
        {
            // Check for valid callback URI
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            if (Request.Uri.GetLeftPart(UriPartial.Path) == uriManager.GenerateCallbackUri(Request.Uri).ToString())
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
            if (Response.StatusCode == 401)
            {
                await LoginRedirectAsync();
            }
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
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            var loginUrl = uriManager.AuthorizationEndpoint;
            var loginParams = uriManager.BuildAuthorizationEndpointContent(Request.Uri, returnUri);

            // Redirect response to login
            Response.Redirect(loginUrl + "?" + await loginParams.ReadAsStringAsync());
        }

        private async Task LogoutRedirectAsync()
        {
            // TODO: Logout

            // Redirect response to post logout URI
            if (Options.PostLogoutRedirectUrl != null)
                Response.Redirect(Options.PostLogoutRedirectUrl);
        }

        private async Task<bool> MakeTokenRequestAsync(string code, string state)
        {
            // Validate passed state
            var stateData = StateCache.ReturnState(state);
            if (stateData == null)
                return
                    await
                        GenerateErrorResponseAsync(HttpStatusCode.BadRequest,
                            "Invalid state: Please reattempt the request");

            // Make HTTP call to token endpoint
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            HttpResponseMessage response;
            try
            {
                var client = new HttpClient();
                response =
                    await
                        client.PostAsync(uriManager.TokenEndpoint,
                            uriManager.BuildTokenEndpointContent(Request.Uri, code));
            }
            catch (Exception exception)
            {
                throw new Exception("Keycloak token endpoint is inaccessible", exception);
            }

            // Check for HTTP errors
            if (!response.IsSuccessStatusCode)
                throw new Exception("Keycloak token endpoint returned an error");

            // Parse response into JSON object (async)
            var contentTask = response.Content.ReadAsStringAsync();
            var payloadJson = await Task.Run(async () => // Run on background thread
            {
                // TODO: Sanity validation below
                var json = JObject.Parse(await contentTask);
                var accessToken = json["access_token"];
                var encodedData = accessToken.ToString().Split('.')[1];
                encodedData += new string('=', encodedData.Length%4);
                var tokenPayload = Encoding.UTF8.GetString(Convert.FromBase64String(encodedData));
                return JObject.Parse(tokenPayload);
            });

            // Load identity and principle to OWIN
            var claims = JwtClaimGenerator.GenerateClaims(payloadJson);
            var identity = new ClaimsIdentity(claims, Options.AuthenticationType, ClaimTypes.Name, ClaimTypes.Role);
            var principal = new ClaimsPrincipal(identity);
            Context.Authentication.User = principal;

            // Redirect to returnUri
            var returnUri = stateData["returnUri"] as Uri ?? new Uri(Request.Uri.GetLeftPart(UriPartial.Authority));
            Response.Redirect(returnUri.ToString());

            // Stop processing OWIN pipeline for redirect
            return true;
        }

        private async Task<bool> GenerateErrorResponseAsync(HttpStatusCode statusCode, string errorMessage)
        {
            // Generate error response
            var task = Response.WriteAsync(errorMessage);
            Response.StatusCode = (int) statusCode;
            Response.ContentType = "text/plain";

            // Stop processing other OWIN middleware
            await task;
            return true;
        }

        #endregion
    }
}
