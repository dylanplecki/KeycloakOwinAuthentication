using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
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
            if (Request.Uri.GetLeftPart(UriPartial.Path) == uriManager.GenerateCallbackUri(Request.Uri).ToString())
            {
                // Create authorization result from query
                var authResult = new AuthorizationResponse(Request.Uri.Query);

                // Check for errors
                authResult.ThrowIfError();

                // Process response
                try
                {
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
            var user = Context.Authentication.User;

            if (user?.Identity != null && user.Identity.IsAuthenticated)
            {
                var result = false;
                if (Options.SaveTokensAsClaims && Options.AutoTokenRefresh)
                    result = await CheckRefreshUserInfo(user);

                if (result) return true;
            }

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
                {StateCache.PropertyNames.AuthenticationProperties, properties}
            };
            var state = StateCache.CreateState(stateData);

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

        private async Task<bool> CheckRefreshUserInfo(ClaimsPrincipal user)
        {
            var claimLookup = user.Claims.ToLookup(c => c.Type, c => c.Value);
            var refreshToken = claimLookup[JwtClaimGenerator.TokenTypes.RefreshToken].FirstOrDefault();
            var accessTokenExpiration =
                claimLookup[JwtClaimGenerator.TokenTypes.AccessTokenExpiration].FirstOrDefault();
            var refreshTokenExpiration =
                claimLookup[JwtClaimGenerator.TokenTypes.RefreshTokenExpiration].FirstOrDefault();

            var accessExpired = DateTime.Parse(accessTokenExpiration) <= DateTime.Now;
            var refreshExpired = DateTime.Parse(refreshTokenExpiration) <= DateTime.Now;

            // Require re-login if refresh token is expired
            if (refreshExpired)
            {
                Context.Authentication.SignOut();
                Response.StatusCode = (int) HttpStatusCode.Unauthorized;
                return true;
            }

            // Get new access token if expired
            if (accessExpired)
            {
                await RefreshUserInfo(refreshToken);
            }

            return false;
        }

        private async Task RefreshUserInfo(string refreshToken)
        {
            var message = new RefreshAccessTokenMessage(Request, Options, refreshToken);
            var claimsTask = message.ExecuteAsync();

            Context.Authentication.SignOut(Options.SignInAsAuthenticationType);
            var identity = new ClaimsIdentity(await claimsTask, Options.SignInAsAuthenticationType);
            Context.Authentication.SignIn(identity);
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
