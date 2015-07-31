using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Keycloak.Models;
using Owin.Security.Keycloak.Models.Messages;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationHandler : AuthenticationHandler<KeycloakAuthenticationOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // Check for valid callback URI
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            if (Request.Uri.GetLeftPart(UriPartial.Path) == uriManager.GetCallbackUri(Request.Uri).ToString())
            {
                // Create authorization result from query
                var authResult = new AuthorizationResponse(Request.Uri.Query);

                try
                {
                    // Check for errors
                    authResult.ThrowIfError();

                    // Process response
                    var message = new RequestAccessTokenMessage(Request, Options, authResult);
                    return await message.ExecuteAsync();
                }
                catch (BadRequestException exception)
                {
                    return await GenerateErrorResponseAsync(HttpStatusCode.BadRequest, exception.Message);
                }
            }

            return null;
        }

        public override async Task<bool> InvokeAsync()
        {
            var ticket = await AuthenticateAsync();
            if (ticket == null) return false;

            if (ticket.Identity != null)
            {
                Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
            }

            // Redirect back to the original secured resource, if any
            if (!string.IsNullOrWhiteSpace(ticket.Properties.RedirectUri))
            {
                Response.Redirect(ticket.Properties.RedirectUri);
                return true;
            }

            return false;
        }

        protected override async Task ApplyResponseGrantAsync()
        {
            var signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);

            if (signout != null)
            {
                await LogoutRedirectAsync(signout.Properties);
            }
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge == null) return;

                await LoginRedirectAsync(challenge.Properties);
            }
        }

        #region OIDC Helper Functions

        private async Task LoginRedirectAsync(AuthenticationProperties properties)
        {
            if (string.IsNullOrEmpty(properties.RedirectUri))
            {
                properties.RedirectUri = Request.Uri.ToString();
            }

            // Create state
            var stateData = new Dictionary<string, object>
            {
                {Constants.CacheTypes.AuthenticationProperties, properties}
            };
            var state = Global.StateCache.CreateState(stateData);

            // Generate login URI
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            var loginUrl = uriManager.AuthorizationEndpoint;
            var loginParams = uriManager.BuildAuthorizationEndpointContent(Request.Uri, state);

            // Redirect response to login
            Response.Redirect(loginUrl + "?" + await loginParams.ReadAsStringAsync());
        }

        private async Task LogoutRedirectAsync(AuthenticationProperties properties)
        {
            // Generate logout URI
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            var logoutUrl = uriManager.EndSessionEndpoint;
            var logoutParams = uriManager.BuildEndSessionEndpointContent(null, properties.RedirectUri);

            // Redirect response to logout
            Response.Redirect(logoutUrl + "?" + await logoutParams.ReadAsStringAsync());
        }

        internal static async Task ValidateCookieIdentity(CookieValidateIdentityContext context)
        {
            if (context.Identity == null || !context.Identity.IsAuthenticated) return;

            var claimLookup = context.Identity.Claims.ToLookup(c => c.Type, c => c.Value);

            var version = claimLookup[Constants.ClaimTypes.Version].FirstOrDefault();
            var authType = claimLookup[Constants.ClaimTypes.AuthenticationType].FirstOrDefault();
            var refreshToken = claimLookup[Constants.ClaimTypes.RefreshToken].FirstOrDefault();

            var accessTokenExpiration =
                claimLookup[Constants.ClaimTypes.AccessTokenExpiration].FirstOrDefault();
            var refreshTokenExpiration =
                claimLookup[Constants.ClaimTypes.RefreshTokenExpiration].FirstOrDefault();

            // Require re-login if cookie is invalid, refresh token expired, or new auth assembly version
            if (refreshToken == null || authType == null || version == null || accessTokenExpiration == null ||
                refreshTokenExpiration == null || DateTime.Parse(refreshTokenExpiration) <= DateTime.Now ||
                !Global.CheckVersion(version))
            {
                context.RejectIdentity();
                return;
            }

            // Get new access token if expired
            if (DateTime.Parse(accessTokenExpiration) <= DateTime.Now)
            {
                KeycloakAuthenticationOptions options;
                if (!Global.KeycloakOptionStore.TryGetValue(authType, out options))
                {
                    context.RejectIdentity();
                    return;
                }

                var message = new RefreshAccessTokenMessage(context.OwinContext.Request, options, refreshToken);
                var claims = await message.ExecuteAsync();
                var identity = new ClaimsIdentity(claims, context.Identity.AuthenticationType);
                context.ReplaceIdentity(identity);
            }
        }

        private async Task<AuthenticationTicket> GenerateErrorResponseAsync(HttpStatusCode statusCode,
            string errorMessage)
        {
            // Generate error response
            var task = Response.WriteAsync(errorMessage);
            Response.StatusCode = (int) statusCode;
            Response.ContentType = "text/plain";

            await task;
            return null;
        }

        #endregion
    }
}