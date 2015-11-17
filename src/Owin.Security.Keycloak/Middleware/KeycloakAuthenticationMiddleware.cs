using System;
using KeycloakIdentityModel;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationMiddleware : AuthenticationMiddleware<KeycloakAuthenticationOptions>
    {
        public KeycloakAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app,
            KeycloakAuthenticationOptions options)
            : base(next, options)
        {
            App = app;
            ValidateOptions();
        }

        private IAppBuilder App { get; }

        protected override AuthenticationHandler<KeycloakAuthenticationOptions> CreateHandler()
        {
            return new KeycloakAuthenticationHandler();
        }

        private void ValidateOptions()
        {
            // Check to ensure authentication type isn't already used
            var authType = Options.AuthenticationType;
            if (!Global.KeycloakOptionStore.TryAdd(authType, Options))
            {
                throw new Exception(
                    $"KeycloakAuthenticationOptions: Authentication type '{authType}' already used; required unique");
            }

            // Verify required options
            if (Options.KeycloakUrl == null)
                ThrowOptionNotFound(nameof(Options.KeycloakUrl));
            if (Options.Realm == null)
                ThrowOptionNotFound(nameof(Options.Realm));

            // Load web root path from config
            if (string.IsNullOrWhiteSpace(Options.VirtualDirectory))
                Options.VirtualDirectory = "/";
            Options.VirtualDirectory = NormalizeUrl(Options.VirtualDirectory);
            if (!Uri.IsWellFormedUriString(Options.VirtualDirectory, UriKind.Relative))
                ThrowInvalidOption(nameof(Options.VirtualDirectory));

            // Set default options
            if (string.IsNullOrWhiteSpace(Options.ResponseType))
                Options.ResponseType = "code";
            if (string.IsNullOrWhiteSpace(Options.Scope))
                Options.Scope = "openid";
            if (string.IsNullOrWhiteSpace(Options.CallbackPath))
                Options.CallbackPath =
                    $"{Options.VirtualDirectory}/owin/security/keycloak/{Uri.EscapeDataString(Options.AuthenticationType)}/callback";
            if (string.IsNullOrWhiteSpace(Options.PostLogoutRedirectUrl))
                Options.PostLogoutRedirectUrl = Options.VirtualDirectory;

            if (Options.SignInAsAuthenticationType == null)
            {
                try
                {
                    Options.SignInAsAuthenticationType = App.GetDefaultSignInAsAuthenticationType();
                }
                catch (Exception)
                {
                    Options.SignInAsAuthenticationType = "";
                }
            }

            // Switch composite options

            if (Options.EnableWebApiMode)
            {
                Options.EnableBearerTokenAuth = true;
                Options.ForceBearerTokenAuth = true;
            }

            // Validate other options
            
            if (Options.ForceBearerTokenAuth && !Options.EnableBearerTokenAuth)
                Options.EnableBearerTokenAuth = true;

            Options.KeycloakUrl = NormalizeUrl(Options.KeycloakUrl);
            Options.CallbackPath = NormalizeUrlPath(Options.CallbackPath);

            // Final parameter validation
            KeycloakIdentity.ValidateParameters(Options);
        }

        private static string NormalizeUrl(string url)
        {
            if (url.EndsWith("/"))
                url = url.TrimEnd('/');
            return url;
        }

        private static string NormalizeUrlPath(string url)
        {
            if (!url.StartsWith("/"))
                url = "/" + url;
            return NormalizeUrl(url);
        }

        private void ThrowOptionNotFound(string optionName)
        {
            var message =
                $"KeycloakAuthenticationOptions [id:{Options.AuthenticationType}] : Required option '{optionName}' not set";
            throw new Exception(message);
        }

        private void ThrowInvalidOption(string optionName, Exception inner = null)
        {
            var message =
                $"KeycloakAuthenticationOptions [id:{Options.AuthenticationType}] : Provided option '{optionName}' is invalid";
            throw inner == null ? new Exception(message) : new Exception(message, inner);
        }
    }
}