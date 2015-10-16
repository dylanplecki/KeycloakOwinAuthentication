using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.IdentityModel.Protocols;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.Keycloak.Utilities.Synchronization;

namespace Owin.Security.Keycloak.Internal
{
    internal class OidcDataManager
    {
        private const string CachedContextPostfix = "_Cached_OidcUriManager";
        private static readonly ReaderWriterLockSlim CacheLock = new ReaderWriterLockSlim();
        private readonly Metadata _metadata = new Metadata();
        private readonly KeycloakAuthenticationOptions _options;
        private DateTime _nextCachedRefreshTime;

        public string Authority { get; }
        public Uri MetadataEndpoint { get; }
        public Uri TokenValidationEndpoint { get; }

        private OidcDataManager(KeycloakAuthenticationOptions options)
        {
            _options = options;
            _nextCachedRefreshTime = DateTime.Now;

            Authority = _options.KeycloakUrl + "/realms/" + _options.Realm;
            MetadataEndpoint = new Uri(Authority + "/" + OpenIdProviderMetadataNames.Discovery);
            TokenValidationEndpoint = new Uri(Authority + "/tokens/validate");
        }

        private class Metadata
        {
            public readonly ReaderWriterLockSlim Lock = new ReaderWriterLockSlim();

            public Uri AuthorizationEndpoint;
            public Uri EndSessionEndpoint;
            public Uri JwksEndpoint;
            public Uri TokenEndpoint;
            public Uri UserInfoEndpoint;

            public string Issuer;
            public JsonWebKeySet Jwks;
        }

        #region Context Caching

        // TODO: Check for multithreading memory contention scenarios
        public static async Task ValidateCachedContextAsync(KeycloakAuthenticationOptions options)
        {
            var context = GetCachedContext(options);
            if (context == null) // Create a new context if required
                await CreateCachedContextAsync(options);
            else if (options.MetadataRefreshInterval >= 0 && context._nextCachedRefreshTime <= DateTime.Now)
                await context.TryRefreshMetadataAsync();
        }

        // TODO: Check for multithreading memory contention scenarios
        public static OidcDataManager GetCachedContext(KeycloakAuthenticationOptions options)
        {
            var context = HttpRuntime.Cache.Get(options.AuthenticationType + CachedContextPostfix) as OidcDataManager;
            if (context == null)
                throw new Exception($"Could not find OIDC data manager for module '{options.AuthenticationType}'");
            return context;
        }

        // TODO: Check for multithreading memory contention scenarios
        public static async Task<OidcDataManager> CreateCachedContextAsync(KeycloakAuthenticationOptions options,
            bool preload = true)
        {
            var cachedContext = new OidcDataManager(options);
            if (preload) await cachedContext.RefreshMetadataAsync();
            HttpRuntime.Cache[options.AuthenticationType + CachedContextPostfix] = cachedContext;
            return cachedContext;
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
                _nextCachedRefreshTime = DateTime.Now.AddSeconds(_options.MetadataRefreshInterval);
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

        public Uri GetCallbackUri(Uri requestUri)
        {
            return new Uri(requestUri.GetLeftPart(UriPartial.Authority) + _options.CallbackPath);
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

        public HttpContent BuildAccessTokenEndpointContent(Uri requestUri, string code)
        {
            // Create parameter dictionary
            var parameters = new Dictionary<string, string>
            {
                {OpenIdConnectParameterNames.RedirectUri, GetCallbackUri(requestUri).ToString()},
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
            else
            {
                parameters.Add(OpenIdConnectParameterNames.PostLogoutRedirectUri,
                    requestUri.GetLeftPart(UriPartial.Authority));
            }

            return new FormUrlEncodedContent(parameters);
        }

        #endregion
    }
}