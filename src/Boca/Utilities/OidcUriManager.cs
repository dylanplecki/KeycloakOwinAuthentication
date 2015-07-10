using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Web;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Boca.Utilities
{
    internal class OidcUriManager
    {
        private const string CachedContextPostfix = "_Cached_BocaUriManager";
        private readonly BocAuthenticationOptions _options;

        public string Issuer { get; private set; }
        public Uri JwksUri { get; private set; }
        public Uri AuthorizationEndpoint { get; private set; }
        public Uri TokenEndpoint { get; private set; }
        public Uri UserInfoEndpoint { get; private set; }

        public static OidcUriManager GetCachedContext(BocAuthenticationOptions options)
        {
            var cachedContext = HttpRuntime.Cache.Get(options.AuthenticationType + CachedContextPostfix) ??
                                new OidcUriManager(options);

            return cachedContext as OidcUriManager;
        }

        public OidcUriManager(BocAuthenticationOptions options)
        {
            _options = options;
            RefreshMetadataAsync();
        }

        public async void RefreshMetadataAsync()
        {
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(_options.MetadataAddress);

            // Fail on unreachable destination
            if (!response.IsSuccessStatusCode)
                throw new Exception(string.Format("RefreshMetadataAsync: Metadata address unreachable ('{0}')",
                    _options.MetadataAddress));

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
                        _options.MetadataAddress), exception);
            }

            // Set internal URI properties
            try
            {
                Issuer = json[OpenIdProviderMetadataNames.Issuer].ToString();
                JwksUri = new Uri(json[OpenIdProviderMetadataNames.JwksUri].ToString());
                AuthorizationEndpoint = new Uri(json[OpenIdProviderMetadataNames.AuthorizationEndpoint].ToString());
                TokenEndpoint = new Uri(json[OpenIdProviderMetadataNames.TokenEndpoint].ToString());
                UserInfoEndpoint = new Uri(json[OpenIdProviderMetadataNames.UserInfoEndpoint].ToString());

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
                        _options.MetadataAddress), exception);
            }
        }

        #region Endpoint Content Builders

        public HttpContent BuildAuthorizationEndpointContent(Uri callbackUri, Uri returnUri)
        {
            // Create state data container
            var stateData = new Dictionary<string, object>
            {
                {"redirectUri", returnUri}
            };

            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, callbackUri.ToString()},
                {OpenIdConnectParameterNames.ResponseType, _options.ResponseType},
                {OpenIdConnectParameterNames.Scope, _options.Scope}
            };

            // Add optional parameters
            if (!string.IsNullOrWhiteSpace(_options.ClientId))
            {
                parameters.Add(OpenIdConnectParameterNames.ClientId, _options.ClientId);

                if (!string.IsNullOrWhiteSpace(_options.ClientSecret))
                    parameters.Add(OpenIdConnectParameterNames.ClientSecret, _options.ClientSecret);
            }

            // Create state in cache
            var state = StateCache.CreateState(stateData);
            parameters.Add(OpenIdConnectParameterNames.State, state);

            return new FormUrlEncodedContent(parameters);
        }

        public HttpContent BuildTokenEndpointContent(string code, string state)
        {
            if (state == null) throw new ArgumentNullException("state");

            // Retrieve state data from cache
            var stateData = StateCache.ReturnState(state);
            if (stateData == null) return null; // Return null on invalid state

            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, stateData["returnUri"] as string},
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

        #endregion
    }
}
