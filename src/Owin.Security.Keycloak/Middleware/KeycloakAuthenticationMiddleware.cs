using System;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationMiddleware : AuthenticationMiddleware<KeycloakAuthenticationOptions>
    {
        private static readonly List<string> ReservedAuthenticationTypes = new List<string>();

        private IAppBuilder App { get; set; }

        public KeycloakAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            KeycloakAuthenticationOptions options)
            : base(next, options)
        {
            App = app;
            ValidateOptions();
        }

        protected override AuthenticationHandler<KeycloakAuthenticationOptions> CreateHandler()
        {
            return new KeycloakAuthenticationHandler();
        }

        private void ValidateOptions()
        {
            // Check to ensure authentication type isn't already used
            var authType = Options.AuthenticationType;
            if (ReservedAuthenticationTypes.Contains(authType))
            {
                throw new Exception(
                    $"KeycloakAuthenticationOptions: Authentication type '{authType}' already used; required unique");
            }
            ReservedAuthenticationTypes.Add(authType);

            // Verify required options
            if (Options.KeycloakUrl == null)
                ThrowOptionNotFound("KeycloakUrl");
            if (Options.Realm == null)
                ThrowOptionNotFound("Realm");

            // Set default options
            if (string.IsNullOrWhiteSpace(Options.ResponseType))
                Options.ResponseType = "code";
            if (string.IsNullOrWhiteSpace(Options.Scope))
                Options.Scope = "openid";
            if (string.IsNullOrWhiteSpace(Options.CallbackPath))
                Options.CallbackPath =
                    $"/owin/security/keycloak/{Uri.EscapeDataString(Options.AuthenticationType)}/callback";
            if (string.IsNullOrWhiteSpace(Options.SignInAsAuthenticationType))
                Options.SignInAsAuthenticationType = App.GetDefaultSignInAsAuthenticationType();

            // Validate options

            if (Options.AutoTokenRefresh && !Options.SaveTokensAsClaims)
                Options.SaveTokensAsClaims = true;

            // ReSharper disable once PossibleNullReferenceException
            if (Options.KeycloakUrl.EndsWith("/"))
                Options.KeycloakUrl = Options.KeycloakUrl.TrimEnd('/');

            // ReSharper disable once PossibleNullReferenceException
            if (!Options.CallbackPath.StartsWith("/"))
                Options.CallbackPath = "/" + Options.CallbackPath;
            if (Options.CallbackPath.EndsWith("/"))
                Options.CallbackPath = Options.CallbackPath.TrimEnd('/');

            if (!Uri.IsWellFormedUriString(Options.KeycloakUrl, UriKind.Absolute))
                ThrowInvalidOption("KeycloakUrl");
            if (!Uri.IsWellFormedUriString(Options.CallbackPath, UriKind.Relative))
                ThrowInvalidOption("CallbackPath");
            if (Options.PostLogoutRedirectUrl != null &&
                !Uri.IsWellFormedUriString(Options.PostLogoutRedirectUrl, UriKind.Absolute))
                ThrowInvalidOption("PostLogoutRedirectUrl");
        }

        private void ThrowOptionNotFound(string optionName)
        {
            var message =
                $"KeycloakAuthenticationOptions [id:{Options.AuthenticationType}] : Required option '{optionName}' not set";
            throw new Exception(message);
        }

        private void ThrowInvalidOption(string optionName)
        {
            var message =
                $"KeycloakAuthenticationOptions [id:{Options.AuthenticationType}] : Provided option '{optionName}' is invalid";
            throw new Exception(message);
        }
    }
}
