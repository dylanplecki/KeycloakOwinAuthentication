using System;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.Keycloak.Middleware
{
    internal class KeycloakAuthenticationMiddleware : AuthenticationMiddleware<BocAuthenticationOptions>
    {
        public KeycloakAuthenticationMiddleware(OwinMiddleware next, BocAuthenticationOptions options)
            : base(next, options)
        {
            ValidateOptions();
        }

        protected override AuthenticationHandler<BocAuthenticationOptions> CreateHandler()
        {
            return new KeycloakAuthenticationHandler();
        }

        private void ValidateOptions()
        {
            // Verify required options
            if (Options.Authority == null)
                ThrowOptionNotFound("Authority");
            if (Options.CallbackPath == null) 
                ThrowOptionNotFound("CallbackPath");

            // ReSharper disable once PossibleNullReferenceException
            if (Options.Authority.EndsWith("/"))
                Options.Authority = Options.Authority.TrimEnd('/');

            // ReSharper disable once PossibleNullReferenceException
            if (!Options.CallbackPath.StartsWith("/"))
                Options.CallbackPath = "/" + Options.CallbackPath;
            if (Options.CallbackPath.EndsWith("/"))
                Options.CallbackPath = Options.CallbackPath.TrimEnd('/');

            // Set default options
            if (Options.MetadataAddress == null)
                Options.MetadataAddress = Options.Authority + "/" + OpenIdProviderMetadataNames.Discovery;
            if (Options.ResponseType == null)
                Options.ResponseType = "code";
            if (Options.Scope == null)
                Options.Scope = "openid";
        }

        private void ThrowOptionNotFound(string optionName)
        {
            var message = string.Format("BocAuthenticationOptions [id:{0}] : Required option '{1}' not set",
                Options.AuthenticationType, optionName);
            throw new Exception(message);
        }
    }
}
