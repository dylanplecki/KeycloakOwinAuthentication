using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;
using System.Web;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Utilities
{
    internal class OidcUriManager
    {
        private const string CachedContextPostfix = "_Cached_OidcUriManager";
        private readonly KeycloakAuthenticationOptions _options;

        public string Issuer { get; private set; }
        public Uri JwksUri { get; private set; }
        public Uri AuthorizationEndpoint { get; private set; }
        public Uri TokenEndpoint { get; private set; }
        public Uri UserInfoEndpoint { get; private set; }
        public Uri EndSessionEndpoint { get; private set; }

        public static async Task<OidcUriManager> GetCachedContext(KeycloakAuthenticationOptions options)
        {
            var cachedContext =
                HttpRuntime.Cache.Get(options.AuthenticationType + CachedContextPostfix) as OidcUriManager;

            if (cachedContext == null)
            {
                cachedContext = new OidcUriManager(options);
                await cachedContext.RefreshMetadataAsync();
            }

            return cachedContext;
        }

        private OidcUriManager(KeycloakAuthenticationOptions options)
        {
            _options = options;
        }

        public async Task RefreshMetadataAsync()
        {
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(_options.GetMetadataUrl());

            // Fail on unreachable destination
            if (!response.IsSuccessStatusCode)
                throw new Exception(string.Format("RefreshMetadataAsync: Metadata address unreachable ('{0}')",
                    _options.GetMetadataUrl()));

            // Try to get the JSON metadata object
            JObject json;
            try
            {
                json = JObject.Parse(await response.Content.ReadAsStringAsync());
            }
            catch (JsonReaderException exception)
            {
                // Fail on invalid JSON
                throw new Exception(
                    string.Format("RefreshMetadataAsync: Metadata address returned invalid JSON object ('{0}')",
                        _options.GetMetadataUrl()), exception);
            }

            // Set internal URI properties
            try
            {
                Issuer = json[OpenIdProviderMetadataNames.Issuer].ToString();
                JwksUri = new Uri(json[OpenIdProviderMetadataNames.JwksUri].ToString());
                AuthorizationEndpoint = new Uri(json[OpenIdProviderMetadataNames.AuthorizationEndpoint].ToString());
                TokenEndpoint = new Uri(json[OpenIdProviderMetadataNames.TokenEndpoint].ToString());
                UserInfoEndpoint = new Uri(json[OpenIdProviderMetadataNames.UserInfoEndpoint].ToString());
                EndSessionEndpoint = new Uri(json[OpenIdProviderMetadataNames.EndSessionEndpoint].ToString());

                // Check for values
                if (AuthorizationEndpoint == null || TokenEndpoint == null || UserInfoEndpoint == null)
                {
                    throw new Exception("One or more metadata endpoints are missing");
                }
            }
            catch (Exception exception)
            {
                // Fail on invalid URI or metadata
                throw new Exception(
                    string.Format("RefreshMetadataAsync: Metadata address returned incomplete data ('{0}')",
                        _options.GetMetadataUrl()), exception);
            }
        }

        public Uri GenerateCallbackUri(Uri requestUri)
        {
            return new Uri(requestUri.GetLeftPart(UriPartial.Authority) + _options.CallbackPath);
        }

        #region Endpoint Content Builders

        public HttpContent BuildAuthorizationEndpointContent(Uri requestUri, string state)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, GenerateCallbackUri(requestUri).ToString()},
                {OpenIdConnectParameterNames.ResponseType, _options.ResponseType},
                {OpenIdConnectParameterNames.Scope, _options.Scope},
                {OpenIdConnectParameterNames.State, state}
            };

            // Add optional parameters
            if (!string.IsNullOrWhiteSpace(_options.ClientId))
            {
                parameters.Add(OpenIdConnectParameterNames.ClientId, _options.ClientId);

                if (!string.IsNullOrWhiteSpace(_options.ClientSecret))
                    parameters.Add(OpenIdConnectParameterNames.ClientSecret, _options.ClientSecret);
            }

            return new FormUrlEncodedContent(parameters);
        }

        public HttpContent BuildTokenEndpointContent(Uri requestUri, string code)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, GenerateCallbackUri(requestUri).ToString()},
                {OpenIdConnectParameterNames.GrantType, "authorization_code"},
                {OpenIdConnectParameterNames.Code, code}
            };

            // Add optional parameters
            if (!string.IsNullOrWhiteSpace(_options.ClientId))
            {
                parameters.Add(OpenIdConnectParameterNames.ClientId, _options.ClientId);

                if (!string.IsNullOrWhiteSpace(_options.ClientSecret))
                    parameters.Add(OpenIdConnectParameterNames.ClientSecret, _options.ClientSecret);
            }

            return new FormUrlEncodedContent(parameters);
        }

        public HttpContent BuildEndSessionEndpointContent(string idToken = null, string postLogoutRedirectUrl = null)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>();
            
            // Add optional parameters
            if (!string.IsNullOrWhiteSpace(idToken))
                parameters.Add(OpenIdConnectParameterNames.IdTokenHint, idToken);

            // Provided postlogouturl takes precedence over options
            if (!string.IsNullOrWhiteSpace(postLogoutRedirectUrl) &&
                Uri.IsWellFormedUriString(postLogoutRedirectUrl, UriKind.Absolute))
            {
                parameters.Add(OpenIdConnectParameterNames.PostLogoutRedirectUri, postLogoutRedirectUrl);
            }
            else if (!string.IsNullOrWhiteSpace(_options.PostLogoutRedirectUrl))
            {
                parameters.Add(OpenIdConnectParameterNames.PostLogoutRedirectUri, _options.PostLogoutRedirectUrl);
            }

            return new FormUrlEncodedContent(parameters);
        }

        #endregion
    }
}
