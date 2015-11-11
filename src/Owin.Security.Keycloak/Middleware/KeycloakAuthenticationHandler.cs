using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.Linq;
using System.Net;
using System.Security.Authentication;
using System.Security.Claims;
using System.Threading.Tasks;
using KeycloakIdentityModel;
using KeycloakIdentityModel.Models.Messages;
using KeycloakIdentityModel.Models.Responses;
using KeycloakIdentityModel.Utilities;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationHandler : AuthenticationHandler<KeycloakAuthenticationOptions>
    {
        private OidcDataManager _oidcManager;

        protected override async Task InitializeCoreAsync()
        {
            // Validate and refresh context-based OIDC manager for the current request
            _oidcManager = await OidcDataManager.ValidateCachedContextAsync(Options);
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
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
                            var identity = await kcIdentity.ValidateIdentity(Options);
                            SignInAsAuthentication(identity, null, Options.SignInAsAuthenticationType);
                            return new AuthenticationTicket(identity, new AuthenticationProperties());
                        }
                        catch (Exception)
                        {
                            // ignored
                        }
                    }
                }

                // If bearer token auth is forced, skip standard auth
                if (Options.ForceBearerTokenAuth) return null;
            }

            return null;
        }

        public override async Task<bool> InvokeAsync()
        {
            // Check SignInAs identity for authentication update
            if (Context.Authentication.User.Identity.IsAuthenticated)
                await ValidateSignInAsIdentities();

            // Check for valid callback URI
            if (!Options.ForceBearerTokenAuth &&
                Request.Uri.GetLeftPart(UriPartial.Path) == _oidcManager.GetCallbackUri(Request.Uri).ToString())
            {
                // Create authorization result from query
                var authResult = new AuthorizationResponse(Request.Uri.Query);

                try
                {
                    // Check for errors
                    authResult.ThrowIfError();

                    // Start verification process async
                    var message = new RequestAccessTokenMessage(Request.Uri, Options, authResult);
                    var messageTask = message.ExecuteAsync();

                    // Validate passed state
                    var stateData = Global.StateCache.ReturnState(authResult.State);
                    if (stateData == null)
                        throw new BadRequestException("Invalid state: Please reattempt the request");

                    // Parse properties from state data
                    var properties =
                        stateData[Constants.CacheTypes.AuthenticationProperties] as AuthenticationProperties ??
                        new AuthenticationProperties();

                    // Process response
                    var identity = await messageTask;
                    SignInAsAuthentication(identity, properties);
                    Context.Authentication.User.AddIdentity(identity);

                    // Redirect back to the original secured resource, if any
                    if (!string.IsNullOrWhiteSpace(properties.RedirectUri) &&
                        Uri.IsWellFormedUriString(properties.RedirectUri, UriKind.Absolute))
                    {
                        Response.Redirect(properties.RedirectUri);
                        return true;
                    }
                }
                catch (BadRequestException exception)
                {
                    await GenerateErrorResponseAsync(HttpStatusCode.BadRequest, "Bad Request", exception.Message);
                    return true;
                }
            }

            return false;
        }

        protected override async Task ApplyResponseGrantAsync()
        {
            if (Options.ForceBearerTokenAuth) return;

            var signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);

            // Signout takes precedence
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

        #region Private Helper Functions

        private void SignInAsAuthentication(ClaimsIdentity identity, AuthenticationProperties authProperties = null,
            string signInAuthType = null)
        {
            if (signInAuthType == Options.AuthenticationType) return;

            var signInIdentity = signInAuthType != null
                ? new ClaimsIdentity(identity.Claims, signInAuthType, identity.NameClaimType, identity.RoleClaimType)
                : identity;

            if (string.IsNullOrWhiteSpace(signInIdentity.AuthenticationType)) return;

            if (authProperties == null)
            {
                authProperties = new AuthenticationProperties
                {
                    // TODO: Make these configurable
                    AllowRefresh = true,
                    IsPersistent = true,
                    ExpiresUtc = DateTime.Now.Add(Options.SignInAsAuthenticationExpiration)
                };
            }

            // Parse expiration date-time
            var expirations = new List<string>
            {
                identity.Claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.RefreshTokenExpiration)?.Value,
                identity.Claims.FirstOrDefault(c => c.Type == Constants.ClaimTypes.AccessTokenExpiration)?.Value
            };

            foreach (var expStr in expirations)
            {
                DateTime expDate;
                if (expStr == null || !DateTime.TryParse(expStr, out expDate)) continue;
                authProperties.ExpiresUtc = expDate.Add(Options.TokenClockSkew);
                break;
            }

            Context.Authentication.SignIn(authProperties, signInIdentity);
        }

        internal async Task ValidateSignInAsIdentities()
        {
            foreach (var origIdentity in Context.Authentication.User.Identities)
            {
                try
                {
                    if (!origIdentity.HasClaim(Constants.ClaimTypes.AuthenticationType, Options.AuthenticationType))
                        continue;

                    var identity = await KeycloakIdentity.ValidateAndRefreshIdentity(origIdentity, Request.Uri, Options);
                    if (identity == null) continue;

                    // Replace identity if expired
                    Context.Authentication.User = new ClaimsPrincipal(identity);
                    SignInAsAuthentication(identity, null, Options.SignInAsAuthenticationType);
                }
                catch (AuthenticationException)
                {
                    Context.Authentication.SignOut(origIdentity.AuthenticationType);
                }
                catch (Exception)
                {
                    // TODO: Some kind of exception logging, maybe log the user out
                    throw;
                }
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

        #endregion
    }
}