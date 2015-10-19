using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel;
using System.IdentityModel.Tokens;
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
            // Get and refresh context-based OIDC manager
            var uriManager = OidcDataManager.GetCachedContext(Options);

            // Check for valid callback URI
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
                    await GenerateErrorResponseAsync(HttpStatusCode.BadRequest, "Bad Request", exception.Message);
                    return null;
                }
            }

            return null;
        }

        public override async Task<bool> InvokeAsync()
        {
            // Validate and refresh context-based OIDC manager for the current request
            await OidcDataManager.ValidateCachedContextAsync(Options);

            // Bearer token authentication override
            if (Options.EnableBearerTokenAuth)
            {
                // Try to authenticate via bearer token auth
                if (Request.Headers.ContainsKey(Constants.BearerTokenHeader))
                {
                    var bearerAuthArr = Request.Headers[Constants.BearerTokenHeader].Trim().Split(new[] {' '}, 2);
                    if ((bearerAuthArr.Length == 2) && bearerAuthArr[0].ToLowerInvariant() == "bearer")
                    {
                        try
                        {
                            var authResponse = new TokenResponse(bearerAuthArr[1], null, null);
                            var kcIdentity = new KeycloakIdentity(authResponse);
                            var identity = await kcIdentity.ValidateIdentity(Options, Options.AuthenticationType);
                            Context.Authentication.User = new ClaimsPrincipal(identity);
                            return false;
                        }
                        catch (Exception)
                        {
                            // ignored
                        }
                    }
                }

                // If bearer token auth is forced, skip standard auth
                if (Options.ForceBearerTokenAuth) return false;
            }

            // Core authentication mechanism
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
            if (Options.ForceBearerTokenAuth) return;

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
                // If bearer token auth is forced, keep returned 401
                if (Options.ForceBearerTokenAuth)
                {
                    await
                        GenerateUnauthorizedResponseAsync(
                            "Access Unauthorized: Requires valid bearer token authorization header");
                    return;
                }

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
            var uriManager = OidcDataManager.GetCachedContext(Options);
            var loginParams = uriManager.BuildAuthorizationEndpointContent(Request.Uri, state);
            var loginUrl = uriManager.GetAuthorizationEndpoint();

            // Redirect response to login
            var loginQueryString = await loginParams.ReadAsStringAsync();
            Response.Redirect(loginUrl + (!string.IsNullOrEmpty(loginQueryString) ? "?" + loginQueryString : ""));
        }

        private async Task LogoutRedirectAsync(AuthenticationProperties properties)
        {
            // Generate logout URI and data
            var uriManager = OidcDataManager.GetCachedContext(Options);
            var logoutParams = uriManager.BuildEndSessionEndpointContent(Request.Uri, null, properties.RedirectUri);
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
                    refreshTokenExpiration == null ||
                    DateTime.Parse(refreshTokenExpiration, CultureInfo.InvariantCulture) <= DateTime.Now ||
                    !Global.CheckVersion(version))
                {
                    throw new AuthenticationException();
                }

                // Get new access token if expired
                if (DateTime.Parse(accessTokenExpiration, CultureInfo.InvariantCulture) <= DateTime.Now)
                {
                    KeycloakAuthenticationOptions options;
                    if (!Global.KeycloakOptionStore.TryGetValue(authType, out options))
                    {
                        throw new AuthenticationException();
                    }

                    var message = new RefreshAccessTokenMessage(context.OwinContext.Request, options, refreshToken);
                    var identity = await message.ExecuteAsync();
                    context.ReplaceIdentity(identity);
                    // TODO: Fix cookie not being sent
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
                throw;
            }
        }

        private async Task GenerateUnauthorizedResponseAsync(string errorMessage)
        {
            await GenerateErrorResponseAsync(Response, HttpStatusCode.Unauthorized, "Unauthorized", errorMessage);
        }

        private async Task GenerateErrorResponseAsync(HttpStatusCode statusCode, string reasonPhrase,
            string errorMessage)
        {
            await GenerateErrorResponseAsync(Response, statusCode, reasonPhrase, errorMessage);
        }

        private static async Task GenerateErrorResponseAsync(IOwinResponse response, HttpStatusCode statusCode,
            string reasonPhrase, string errorMessage)
        {
            // Generate error response
            var task = response.WriteAsync(errorMessage);
            response.StatusCode = (int) statusCode;
            response.ReasonPhrase = reasonPhrase;
            response.ContentType = "text/plain";
            await task;
        }

        #endregion
    }
}