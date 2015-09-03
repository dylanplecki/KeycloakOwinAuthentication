using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.Linq;
using System.Net;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Keycloak.Internal;
using Owin.Security.Keycloak.Models.Messages;
using Owin.Security.Keycloak.Models.Responses;

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
                    await GenerateErrorResponseAsync(HttpStatusCode.BadRequest, exception.Message);
                    return null;
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

            // Generate login URI and data
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            var loginParams = uriManager.BuildAuthorizationEndpointContent(Request.Uri, state);
            var loginUrl = uriManager.GetAuthorizationEndpoint();

            // Redirect response to login
            var loginQueryString = await loginParams.ReadAsStringAsync();
            Response.Redirect(loginUrl + (!string.IsNullOrEmpty(loginQueryString) ? "?" + loginQueryString : ""));
        }

        private async Task LogoutRedirectAsync(AuthenticationProperties properties)
        {
            // Generate logout URI and data
            var uriManager = await OidcUriManager.GetCachedContext(Options);
            var logoutParams = uriManager.BuildEndSessionEndpointContent(null, properties.RedirectUri);
            var logoutUrl = uriManager.GetEndSessionEndpoint();

            // Redirect response to logout
            var logoutQueryString = await logoutParams.ReadAsStringAsync();
            Response.Redirect(logoutUrl + (!string.IsNullOrEmpty(logoutQueryString) ? "?" + logoutQueryString : ""));
        }

        internal static async Task ValidateCookieIdentity(CookieValidateIdentityContext context)
        {
            if (context == null) throw new ArgumentNullException();
            if (context.Identity == null || !context.Identity.IsAuthenticated) return;

            try
            {
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
                    throw new AuthenticationException();
                }

                // Get new access token if expired
                if (DateTime.Parse(accessTokenExpiration) <= DateTime.Now)
                {
                    KeycloakAuthenticationOptions options;
                    if (!Global.KeycloakOptionStore.TryGetValue(authType, out options))
                    {
                        throw new AuthenticationException();
                    }

                    var message = new RefreshAccessTokenMessage(context.OwinContext.Request, options, refreshToken);
                    var claims = await message.ExecuteAsync();
                    var identity = new ClaimsIdentity(claims, context.Identity.AuthenticationType);
                    context.ReplaceIdentity(identity);
                }
            }
            catch (AuthenticationException)
            {
                context.RejectIdentity();
            }
            catch (Exception)
            {
                context.RejectIdentity();
                // TODO: Some kind of exception logging
            }
        }

        private async Task GenerateErrorResponseAsync(HttpStatusCode statusCode,
            string errorMessage)
        {
            await GenerateErrorResponseAsync(Response, statusCode, errorMessage);
        }

        private static async Task GenerateErrorResponseAsync(IOwinResponse response, HttpStatusCode statusCode,
            string errorMessage)
        {
            // Generate error response
            var task = response.WriteAsync(errorMessage);
            response.StatusCode = (int) statusCode;
            response.ContentType = "text/plain";
            await task;
        }

        #endregion
    }
}