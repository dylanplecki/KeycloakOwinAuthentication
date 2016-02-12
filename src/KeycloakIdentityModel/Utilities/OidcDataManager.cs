using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using KeycloakIdentityModel.Models.Configuration;
using KeycloakIdentityModel.Utilities.Synchronization;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace KeycloakIdentityModel.Utilities
{
    public class OidcDataManager
    {
        private static readonly Dictionary<string, OidcDataManager> OidcManagerCache =
            new Dictionary<string, OidcDataManager>();

        private const string CachedContextPostfix = "_Cached_OidcUriManager";
        private readonly Metadata _metadata = new Metadata();
        private readonly IKeycloakParameters _options;
        private readonly ReaderWriterLockSlim _refreshLock = new ReaderWriterLockSlim();

        // Thread-safe pipeline locks
        private bool _cacheRefreshing;
        private DateTime _nextCachedRefreshTime;

        protected OidcDataManager(IKeycloakParameters options)
        {
            _options = options;
            _nextCachedRefreshTime = DateTime.Now;

            Authority = _options.KeycloakUrl + "/realms/" + _options.Realm;
            MetadataEndpoint = new Uri(Authority + "/" + OpenIdProviderMetadataNames.Discovery);
            TokenValidationEndpoint = new Uri(Authority + "/tokens/validate");
        }

        public string Authority { get; }
        public Uri MetadataEndpoint { get; }
        public Uri TokenValidationEndpoint { get; }

        private class Metadata
        {
            public readonly ReaderWriterLockSlim Lock = new ReaderWriterLockSlim();

            public Uri AuthorizationEndpoint;
            public Uri EndSessionEndpoint;

            public string Issuer;
            public JsonWebKeySet Jwks;
            public Uri JwksEndpoint;
            public Uri TokenEndpoint;
            public Uri UserInfoEndpoint;
        }

        #region Context Caching

        public static Task ValidateCachedContextAsync(IKeycloakParameters options)
        {
            var context = GetCachedContext(options.AuthenticationType);
            return context.ValidateCachedContextAsync();
        }

        private async Task ValidateCachedContextAsync()
        {
            using (var guard = new UpgradeableGuard(_refreshLock))
            {
                if (_cacheRefreshing || _nextCachedRefreshTime > DateTime.Now)
                    return;
                guard.UpgradeToWriterLock();
                if (_cacheRefreshing) return; // Double-check after writer upgrade
                _cacheRefreshing = true;
            }

            if (_nextCachedRefreshTime <= DateTime.Now)
                await RefreshMetadataAsync();

            using (new WriterGuard(_refreshLock))
            {
                _cacheRefreshing = false;
            }
        }

        public static OidcDataManager GetCachedContext(IKeycloakParameters options)
        {
            return GetCachedContext(options.AuthenticationType);
        }

        public static OidcDataManager GetCachedContext(string authType)
        {
            var context = GetCachedContextSafe(authType);
            if (context == null)
                throw new Exception($"Could not find cached OIDC data manager for module '{authType}'");
            return context;
        }

        public static Task<OidcDataManager> GetCachedContextAsync(IKeycloakParameters options)
        {
            var context = GetCachedContextSafe(options.AuthenticationType);
            return context != null ? Task.FromResult(context) : CreateCachedContext(options);
        }

        private static OidcDataManager GetCachedContextSafe(string authType)
        {
            OidcDataManager result;
            return OidcManagerCache.TryGetValue(authType + CachedContextPostfix, out result) ? result : null;
        }

        public static async Task<OidcDataManager> CreateCachedContext(IKeycloakParameters options,
            bool preload = true)
        {
            var newContext = new OidcDataManager(options);
            OidcManagerCache[options.AuthenticationType + CachedContextPostfix] = newContext;
            if (preload) await newContext.ValidateCachedContextAsync();
            return newContext;
        }

        #endregion

        #region Metadata Handling

        public async Task<bool> TryRefreshMetadataAsync()
        {
            try
            {
                await RefreshMetadataAsync();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public async Task RefreshMetadataAsync()
        {
            // Get Metadata from endpoint
            var dataTask = HttpApiGet(MetadataEndpoint);

            // Try to get the JSON metadata object
            JObject json;
            try
            {
                json = JObject.Parse(await dataTask);
            }
            catch (JsonReaderException exception)
            {
                // Fail on invalid JSON
                throw new Exception(
                    $"RefreshMetadataAsync: Metadata address returned invalid JSON object ('{MetadataEndpoint}')",
                    exception);
            }

            // Set internal URI properties
            try
            {
                // Preload required data fields
                var jwksEndpoint = new Uri(json[OpenIdProviderMetadataNames.JwksUri].ToString());
                var jwks = new JsonWebKeySet(await HttpApiGet(jwksEndpoint));

                using (new WriterGuard(_metadata.Lock))
                {
                    _metadata.Jwks = jwks;
                    _metadata.JwksEndpoint = jwksEndpoint;
                    _metadata.Issuer = json[OpenIdProviderMetadataNames.Issuer].ToString();
                    _metadata.AuthorizationEndpoint =
                        new Uri(json[OpenIdProviderMetadataNames.AuthorizationEndpoint].ToString());
                    _metadata.TokenEndpoint =
                        new Uri(json[OpenIdProviderMetadataNames.TokenEndpoint].ToString());
                    _metadata.UserInfoEndpoint =
                        new Uri(json[OpenIdProviderMetadataNames.UserInfoEndpoint].ToString());
                    _metadata.EndSessionEndpoint =
                        new Uri(json[OpenIdProviderMetadataNames.EndSessionEndpoint].ToString());

                    // Check for values
                    if (_metadata.AuthorizationEndpoint == null || _metadata.TokenEndpoint == null ||
                        _metadata.UserInfoEndpoint == null)
                    {
                        throw new Exception("One or more metadata endpoints are missing");
                    }
                }

                // Update refresh time
                _nextCachedRefreshTime = DateTime.Now.Add(_options.MetadataRefreshInterval);
            }
            catch (Exception exception)
            {
                // Fail on invalid URI or metadata
                throw new Exception(
                    $"RefreshMetadataAsync: Metadata address returned incomplete data ('{MetadataEndpoint}')", exception);
            }
        }

        private static async Task<string> HttpApiGet(Uri uri)
        {
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(uri);

            // Fail on unreachable destination
            if (!response.IsSuccessStatusCode)
                throw new Exception(
                    $"RefreshMetadataAsync: HTTP address unreachable ('{uri}')");

            return await response.Content.ReadAsStringAsync();
        }

        #endregion

        #region Metadata Info Getters

        public Uri GetCallbackUri(Uri baseUri)
        {
            return new Uri(baseUri.GetLeftPart(UriPartial.Authority) + _options.CallbackPath);
        }

        public string GetIssuer()
        {
            using (new ReaderGuard(_metadata.Lock))
            {
                return _metadata.Issuer;
            }
        }

        public Uri GetJwksUri()
        {
            using (new ReaderGuard(_metadata.Lock))
            {
                return _metadata.JwksEndpoint;
            }
        }

        public Uri GetAuthorizationEndpoint()
        {
            using (new ReaderGuard(_metadata.Lock))
            {
                return _metadata.AuthorizationEndpoint;
            }
        }

        public Uri GetTokenEndpoint()
        {
            using (new ReaderGuard(_metadata.Lock))
            {
                return _metadata.TokenEndpoint;
            }
        }

        public Uri GetUserInfoEndpoint()
        {
            using (new ReaderGuard(_metadata.Lock))
            {
                return _metadata.UserInfoEndpoint;
            }
        }

        public Uri GetEndSessionEndpoint()
        {
            using (new ReaderGuard(_metadata.Lock))
            {
                return _metadata.EndSessionEndpoint;
            }
        }

        public JsonWebKeySet GetJsonWebKeys()
        {
            using (new ReaderGuard(_metadata.Lock))
            {
                return _metadata.Jwks;
            }
        }

        #endregion

        #region Endpoint Content Builders

        public HttpContent BuildAuthorizationEndpointContent(Uri requestUri, string state)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, GetCallbackUri(requestUri).ToString()},
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

            if (!string.IsNullOrWhiteSpace(_options.IdentityProvider))
                parameters.Add(Constants.KeycloakParameters.IdpHint, _options.IdentityProvider);

            return new FormUrlEncodedContent(parameters);
        }

        public HttpContent BuildAccessTokenEndpointContent(Uri baseUri, string code)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, GetCallbackUri(baseUri).ToString()},
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

        public HttpContent BuildRefreshTokenEndpointContent(string refreshToken)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.GrantType, "refresh_token"},
                {OpenIdConnectParameterNames.Scope, _options.Scope},
                {"refresh_token", refreshToken}
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

        public HttpContent BuildEndSessionEndpointContent(Uri requestUri, string idToken = null,
            string postLogoutRedirectUrl = null)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>();

            // Add optional parameters
            if (!string.IsNullOrWhiteSpace(idToken))
                parameters.Add(OpenIdConnectParameterNames.IdTokenHint, idToken);

            // Add postLogoutRedirectUrl to parameters
            if (string.IsNullOrEmpty(postLogoutRedirectUrl))
                postLogoutRedirectUrl = _options.PostLogoutRedirectUrl;

            if (string.IsNullOrEmpty(postLogoutRedirectUrl)) // Double-check options for empty/null
                postLogoutRedirectUrl = requestUri.GetLeftPart(UriPartial.Authority);
            else if (Uri.IsWellFormedUriString(postLogoutRedirectUrl, UriKind.Relative))
                postLogoutRedirectUrl = requestUri.GetLeftPart(UriPartial.Authority) + postLogoutRedirectUrl;

            if (!Uri.IsWellFormedUriString(postLogoutRedirectUrl, UriKind.RelativeOrAbsolute))
                throw new Exception("Invalid PostLogoutRedirectUrl option: Not a valid relative/absolute URL");

            parameters.Add(OpenIdConnectParameterNames.PostLogoutRedirectUri, postLogoutRedirectUrl);

            return new FormUrlEncodedContent(parameters);
        }

        #endregion
    }
}