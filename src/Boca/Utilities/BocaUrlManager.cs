using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Web;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Boca.Utilities
{
    internal class BocaUrlManager
    {
        private const string CachedContextPostfix = "_Cached_BocaUrlManager";
        private readonly BocAuthenticationOptions _options;

        public static BocaUrlManager GetCachedContext(BocAuthenticationOptions options, bool initializeMetadata = true)
        {
            var cachedContext = HttpRuntime.Cache.Get(options.AuthenticationType + CachedContextPostfix) ??
                                new BocaUrlManager(options, initializeMetadata);

            return cachedContext as BocaUrlManager;
        }

        public BocaUrlManager(BocAuthenticationOptions options, bool initializeMetadata = true)
        {
            _options = options;

            if (initializeMetadata)
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
                _authorizationEndpoint = new Uri(json["authorization_endpoint"].ToString());
                _tokenEndpoint = new Uri(json["token_endpoint"].ToString());
                _userInfoEndpoint = new Uri(json["userinfo_endpoint"].ToString());

                // Check for values
                if (_authorizationEndpoint == null || _tokenEndpoint == null || _userInfoEndpoint == null)
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

        #region Endpoint Getters

        private Uri _authorizationEndpoint;

        public Uri AuthorizationEndpoint
        {
            get
            {
                return _authorizationEndpoint ??
                       new Uri(_options.Authority + "/" + OpenIdProviderMetadataNames.AuthorizationEndpoint);
            }
        }

        private Uri _tokenEndpoint;

        public Uri TokenEndpoint
        {
            get
            {
                return _tokenEndpoint ??
                       new Uri(_options.Authority + "/" + OpenIdProviderMetadataNames.TokenEndpoint);
            }
        }

        private Uri _userInfoEndpoint;

        public Uri UserInfoEndpoint
        {
            get
            {
                return _userInfoEndpoint ??
                       new Uri(_options.Authority + "/" + OpenIdProviderMetadataNames.UserInfoEndpoint);
            }
        }

        #endregion

        #region Endpoint Content Builders

        public HttpContent BuildAuthorizationEndpointContent(string redirectUri)
        {
            // Create state data container
            var stateData = new Dictionary<string, object>
            {
                {"redirectUri", redirectUri}
            };

            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, redirectUri},
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

        public HttpContent BuildTokenEndpointContent(string state)
        {
            var stateData = StateCache.ReturnState(state);

            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, stateData["returnUri"] as string}
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
