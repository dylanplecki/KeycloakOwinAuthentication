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
        private readonly IKeycloakOptions _options;

        public string Issuer { get; private set; }
        public Uri JwksUri { get; private set; }
        public Uri AuthorizationEndpoint { get; private set; }
        public Uri TokenEndpoint { get; private set; }
        public Uri UserInfoEndpoint { get; private set; }
        public Uri EndSessionEndpoint { get; private set; }

        public Uri Authority => new Uri(_options.KeycloakUrl + "/realms/" + _options.Realm);
        public Uri MetadataEndpoint => new Uri(Authority, OpenIdProviderMetadataNames.Discovery);

        public static async Task<OidcUriManager> GetCachedContext(IKeycloakOptions options)
        {
            OidcUriManager cachedContext;
            TryGetCachedContext(options.AuthenticationType, out cachedContext);

            if (cachedContext == null)
            {
                cachedContext = new OidcUriManager(options);
                await cachedContext.RefreshMetadataAsync();
            }

            return cachedContext;
        }

        public static bool TryGetCachedContext(string authenticationType, out OidcUriManager context)
        {
            context = HttpRuntime.Cache.Get(authenticationType + CachedContextPostfix) as OidcUriManager;
            return context != null;
        }

        private OidcUriManager(IKeycloakOptions options)
        {
            _options = options;
        }

        public async Task RefreshMetadataAsync()
        {
            var httpClient = new HttpClient();
            var response = await httpClient.GetAsync(MetadataEndpoint);

            // Fail on unreachable destination
            if (!response.IsSuccessStatusCode)
                throw new Exception(
                    $"RefreshMetadataAsync: Metadata address unreachable ('{MetadataEndpoint}')");

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
                    $"RefreshMetadataAsync: Metadata address returned invalid JSON object ('{MetadataEndpoint}')", exception);
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
                    $"RefreshMetadataAsync: Metadata address returned incomplete data ('{MetadataEndpoint}')", exception);
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

        public HttpContent BuildAccessTokenEndpointContent(Uri requestUri, string code)
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
