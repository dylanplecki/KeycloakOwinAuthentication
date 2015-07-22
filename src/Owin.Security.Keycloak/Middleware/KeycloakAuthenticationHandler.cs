using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.Keycloak.Models;
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
                return await MakeTokenRequestAsync(authResult.Code, authResult.State);
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

        private async Task<AuthenticationTicket> MakeTokenRequestAsync(string code, string state)
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

            // Generate claims and create user information
            var claims =
                await
                    JwtClaimGenerator.GenerateClaimsAsync(await response.Content.ReadAsStringAsync(),
                        Options.SaveTokensAsClaims);
            var identity = new ClaimsIdentity(claims, Options.SignInAsAuthenticationType);
            var properties = stateData[StateCache.PropertyNames.AuthenticationProperties] as AuthenticationProperties ??
                             new AuthenticationProperties();

            return new AuthenticationTicket(identity, properties);
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
