using System;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationMiddleware : AuthenticationMiddleware<KeycloakAuthenticationOptions>
    {
        public KeycloakAuthenticationMiddleware(OwinMiddleware next, KeycloakAuthenticationOptions options)
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
            // Verify required options
            if (Options.KeycloakUrl == null)
                ThrowOptionNotFound("KeycloakUrl");
            if (Options.Realm == null)
                ThrowOptionNotFound("Realm");
            if (Options.CallbackPath == null) 
                ThrowOptionNotFound("CallbackPath");

            // ReSharper disable once PossibleNullReferenceException
            if (Options.KeycloakUrl.EndsWith("/"))
                Options.KeycloakUrl = Options.KeycloakUrl.TrimEnd('/');

            // ReSharper disable once PossibleNullReferenceException
            if (!Options.CallbackPath.StartsWith("/"))
                Options.CallbackPath = "/" + Options.CallbackPath;
            if (Options.CallbackPath.EndsWith("/"))
                Options.CallbackPath = Options.CallbackPath.TrimEnd('/');

            // Set default options
            if (Options.ResponseType == null)
                Options.ResponseType = "code";
            if (Options.Scope == null)
                Options.Scope = "openid";
        }

        private void ThrowOptionNotFound(string optionName)
        {
            var message = string.Format("KeycloakAuthenticationOptions [id:{0}] : Required option '{1}' not set",
                Options.AuthenticationType, optionName);
            throw new Exception(message);
        }
    }
}
