using System;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationMiddleware : AuthenticationMiddleware<KeycloakAuthenticationOptions>
    {
        private static readonly List<string> ReservedAuthenticationTypes = new List<string>();

        public KeycloakAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            KeycloakAuthenticationOptions options)
            : base(next, options)
        {
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
                    string.Format(
                        "KeycloakAuthenticationOptions: Authentication type '{0}' already used; required unique",
                        authType));
            }
            ReservedAuthenticationTypes.Add(authType);

            // Verify required options
            if (Options.KeycloakUrl == null)
                ThrowOptionNotFound("KeycloakUrl");
            if (Options.Realm == null)
                ThrowOptionNotFound("Realm");

            // Set default options
            if (Options.ResponseType == null)
                Options.ResponseType = "code";
            if (Options.Scope == null)
                Options.Scope = "openid";
            if (Options.CallbackPath == null)
                Options.CallbackPath = string.Format("/owin/security/keycloak/{0}/callback",
                    Uri.EscapeDataString(Options.AuthenticationType));

            // Validate options

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
            var message = string.Format("KeycloakAuthenticationOptions [id:{0}] : Required option '{1}' not set",
                Options.AuthenticationType, optionName);
            throw new Exception(message);
        }

        private void ThrowInvalidOption(string optionName)
        {
            var message = string.Format("KeycloakAuthenticationOptions [id:{0}] : Provided option '{1}' is invalid",
                Options.AuthenticationType, optionName);
            throw new Exception(message);
        }
    }
}
