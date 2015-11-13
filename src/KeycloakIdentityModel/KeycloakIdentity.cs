using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using KeycloakIdentityModel.Extensions;
using KeycloakIdentityModel.Models.Configuration;
using KeycloakIdentityModel.Models.Messages;
using KeycloakIdentityModel.Models.Responses;
using KeycloakIdentityModel.Utilities;
using KeycloakIdentityModel.Utilities.ClaimMapping;
using Newtonsoft.Json.Linq;

namespace KeycloakIdentityModel
{
    public class KeycloakIdentity : ClaimsIdentity, IIdentity
    {
        private JwtSecurityToken _accessToken;
        private JwtSecurityToken _idToken;
        private JwtSecurityToken _refreshToken;

        private readonly IKeycloakParameters _parameters;

        private readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1);
        private readonly List<Claim> _userClaims = new List<Claim>();
        private IEnumerable<Claim> _kcClaims;

        /// <summary>
        ///     Load a new Keycloak-based identity from a claims identity
        /// </summary>
        /// <param name="parameters"></param>
        protected KeycloakIdentity(IKeycloakParameters parameters)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (ValidateParameters(parameters))
                throw new ArgumentException("Invalid IKeycloakParameters passed to KeycloakIdentity");
            _parameters = parameters;
        }

        #region Public Methods

        /// <summary>
        ///     Gets the authentication type
        /// </summary>
        public override string AuthenticationType => _parameters.AuthenticationType;

        /// <summary>
        ///     Gets a value that indicates whether the identity has been authenticated
        /// </summary>
        public override bool IsAuthenticated => _kcClaims != null && _accessToken.ValidTo > DateTime.Now;

        /// <summary>
        ///     Gets the claims associated with this claims identity
        /// </summary>
        public override IEnumerable<Claim> Claims
        {
            get
            {
                lock (_refreshLock)
                {
                    return GetCurrentClaims();
                }
            }
        }

        /// <summary>
        ///     Adds a single claim to this identity
        /// </summary>
        /// <param name="claim"></param>
        [SecurityCritical]
        public override void AddClaim(Claim claim)
        {
            _userClaims.Add(claim);
        }

        /// <summary>
        ///     Adds a list of claims to this claims identity
        /// </summary>
        /// <param name="claims"></param>
        [SecurityCritical]
        public override void AddClaims(IEnumerable<Claim> claims)
        {
            _userClaims.AddRange(claims);
        }

        /// <summary>
        ///     Attempts to remove a claim from the claims identity
        /// </summary>
        /// <param name="claim"></param>
        [SecurityCritical]
        public override void RemoveClaim(Claim claim)
        {
            if (!TryRemoveClaim(claim))
                throw new InvalidOperationException();
        }

        /// <summary>
        ///     Attempts to remove a claim from the claims identity
        /// </summary>
        /// <param name="claim"></param>
        /// <returns></returns>
        [SecurityCritical]
        public override bool TryRemoveClaim(Claim claim)
        {
            return _userClaims.Remove(claim);
        }

        /// <summary>
        ///     Returns a new System.Security.Claims.ClaimsIdentity copied from this claims identity
        /// </summary>
        /// <returns></returns>
        public override ClaimsIdentity Clone()
        {
            return Task.Run(ToClaimsIdentityAsync).Result;
        }

        /// <summary>
        ///     Refreshes and re-authenticates the current identity from the Keycloak instance (only if necessary)
        /// </summary>
        /// <returns></returns>
        public Task RefreshIdentityAsync()
        {
            return GetClaimsAsync();
        }

        /// <summary>
        ///     Refreshes and returns the updated claims for the identity (refreshes only if necessary)
        /// </summary>
        /// <returns></returns>
        public Task<IEnumerable<Claim>> GetUpdatedClaimsAsync()
        {
            return GetClaimsAsync();
        }

        /// <summary>
        ///     Returns a static base representation of the identity as a claims identity
        /// </summary>
        /// <returns></returns>
        public async Task<ClaimsIdentity> ToClaimsIdentityAsync()
        {
            return new ClaimsIdentity(await GetClaimsAsync(), AuthenticationType);
        }

        #endregion

        #region Public Static Methods

        /// <summary>
        ///     Converts a keycloak-generated claims identity into a Keycloak identity
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="identity"></param>
        /// <returns></returns>
        public static Task<KeycloakIdentity> ConvertFromClaimsIdentityAsync(IKeycloakParameters parameters,
            ClaimsIdentity identity)
        {
            return ConvertFromClaimsAsync(parameters, identity.Claims);
        }

        /// <summary>
        ///     Converts a keycloak-generated claims list into a Keycloak identity
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="claims"></param>
        /// <returns></returns>
        public static async Task<KeycloakIdentity> ConvertFromClaimsAsync(IKeycloakParameters parameters,
            IEnumerable<Claim> claims)
        {
            var kcIdentity = new KeycloakIdentity(parameters);
            await kcIdentity.ImportClaims(claims);
            return kcIdentity;
        }

        /// <summary>
        ///     Converts a JWT token-response endpoint message into a Keycloak identity
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public static async Task<KeycloakIdentity> ConvertFromTokenResponseAsync(IKeycloakParameters parameters,
            TokenResponse message)
        {
            var kcIdentity = new KeycloakIdentity(parameters);
            await kcIdentity.ImportTokenResponse(message);
            return kcIdentity;
        }

        /// <summary>
        ///     Converts a set of JWTs into a Keycloak identity
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="accessToken"></param>
        /// <param name="refreshToken"></param>
        /// <param name="idToken"></param>
        /// <returns></returns>
        public static async Task<KeycloakIdentity> ConvertFromJwtAsync(IKeycloakParameters parameters,
            string accessToken, string refreshToken = null, string idToken = null)
        {
            var kcIdentity = new KeycloakIdentity(parameters);
            await kcIdentity.ImportJwt(accessToken, refreshToken, idToken);
            return kcIdentity;
        }

        /// <summary>
        ///     Generates the OpenID Connect compliant Keycloak login URL
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="baseUri"></param>
        /// <param name="state"></param>
        /// <returns></returns>
        public static async Task<Uri> GenerateLoginUriAsync(IKeycloakParameters parameters, Uri baseUri,
            string state = null)
        {
            // Generate login URI and data
            var uriManager = await OidcDataManager.GetCachedContextAsync(parameters);
            var loginParams = uriManager.BuildAuthorizationEndpointContent(baseUri, state ?? Guid.NewGuid().ToString());
            var loginUrl = uriManager.GetAuthorizationEndpoint();

            // Return login URI
            var loginQueryString = await loginParams.ReadAsStringAsync();
            return new Uri(loginUrl + (!string.IsNullOrEmpty(loginQueryString) ? "?" + loginQueryString : ""));
        }

        /// <summary>
        ///     Generates the local URL on which to accept OIDC callbacks from Keycloak
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="baseUri"></param>
        /// <returns></returns>
        public static async Task<Uri> GenerateLoginCallbackUriAsync(IKeycloakParameters parameters, Uri baseUri)
        {
            return (await OidcDataManager.GetCachedContextAsync(parameters)).GetCallbackUri(baseUri);
        }

        /// <summary>
        ///     Generates the OpenID Connect compliant Keycloak logout URL
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="baseUri"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        public static async Task<Uri> GenerateLogoutUriAsync(IKeycloakParameters parameters, Uri baseUri,
            Uri redirectUri)
        {
            // Generate logout URI and data
            var uriManager = await OidcDataManager.GetCachedContextAsync(parameters);
            var logoutParams = uriManager.BuildEndSessionEndpointContent(baseUri, null, redirectUri.ToString());
            var logoutUrl = uriManager.GetEndSessionEndpoint();

            // Return logout URI
            var logoutQueryString = await logoutParams.ReadAsStringAsync();
            return new Uri(logoutUrl + (!string.IsNullOrEmpty(logoutQueryString) ? "?" + logoutQueryString : ""));
        }

        /// <summary>
        ///     Validates an IKeycloakParameters object for completeness and correctness
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static bool ValidateParameters(IKeycloakParameters parameters)
        {
            // Verify required parameters
            if (parameters.KeycloakUrl == null)
                return false;
            if (parameters.Realm == null)
                return false;

            // Set default parameters
            if (string.IsNullOrWhiteSpace(parameters.ResponseType))
                return false;
            if (string.IsNullOrWhiteSpace(parameters.Scope))
                return false;
            if (string.IsNullOrWhiteSpace(parameters.CallbackPath))
                return false;
            if (string.IsNullOrWhiteSpace(parameters.PostLogoutRedirectUrl))
                return false;

            // Validate other parameters
            if (!Uri.IsWellFormedUriString(parameters.KeycloakUrl, UriKind.Absolute))
                return false;
            if (!Uri.IsWellFormedUriString(parameters.CallbackPath, UriKind.Relative))
                return false;
            if (parameters.PostLogoutRedirectUrl != null &&
                !Uri.IsWellFormedUriString(parameters.PostLogoutRedirectUrl, UriKind.RelativeOrAbsolute))
                return false;

            // Attempt to refresh OIDC metadata from endpoint (on seperate thread)
            try
            {
                Task.Run(() => OidcDataManager.GetCachedContextAsync(parameters)).Wait();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        #endregion

        #region Import Methods

        /// <summary>
        ///     Import a new identity from a ClaimsIdentity
        /// </summary>
        /// <param name="claims"></param>
        /// <returns></returns>
        protected Task ImportClaims(IEnumerable<Claim> claims)
        {
            var claimLookup = claims.ToLookup(c => c.Type, c => c.Value);

            var refreshToken = claimLookup[Constants.ClaimTypes.RefreshToken].FirstOrDefault();
            var idToken = claimLookup[Constants.ClaimTypes.IdToken].FirstOrDefault();
            var accessToken = claimLookup[Constants.ClaimTypes.AccessToken].FirstOrDefault();

            return ImportJwt(accessToken, idToken, refreshToken);
        }

        /// <summary>
        ///     Import a new identity from a TokenResponse message
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        protected Task ImportTokenResponse(TokenResponse message)
        {
            return ImportJwt(message.AccessToken, message.IdToken, message.RefreshToken);
        }

        /// <summary>
        ///     Import a new identity from a set of JWTs
        /// </summary>
        /// <param name="accessToken"></param>
        /// <param name="idToken"></param>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        protected async Task ImportJwt(string accessToken, string refreshToken = null, string idToken = null)
        {
            if (accessToken == null) throw new ArgumentException(nameof(accessToken));

            // Validate JWTs provided
            var tokenHandler = new KeycloakTokenHandler();
            var uriManager = await OidcDataManager.GetCachedContextAsync(_parameters);
            
            SecurityToken accessSecurityToken = null, idSecurityToken = null, refreshSecurityToken = null;
            
            if (_parameters.UseRemoteTokenValidation)
            {
                accessSecurityToken = await KeycloakTokenHandler.ValidateTokenRemote(accessToken, uriManager);
            }
            else
            {
                accessSecurityToken = tokenHandler.ValidateToken(accessToken, _parameters, uriManager);
            }

            if (accessSecurityToken == null)
                throw new Exception("Internal error: Invalid access token; valid required");

            if (idToken != null)
                tokenHandler.TryValidateToken(idToken, _parameters, uriManager, out idSecurityToken);
            if (refreshToken != null)
                tokenHandler.TryValidateToken(refreshToken, _parameters, uriManager, out refreshSecurityToken);

            // Save to this object
            // TODO: Convert to MS claims parsing in token handler
            _kcClaims = GenerateJwtClaims(accessSecurityToken as JwtSecurityToken, idSecurityToken as JwtSecurityToken,
                refreshSecurityToken as JwtSecurityToken);
            _idToken = idSecurityToken as JwtSecurityToken;
            _accessToken = accessSecurityToken as JwtSecurityToken;
            _refreshToken = refreshSecurityToken as JwtSecurityToken;
        }

        #endregion

        #region Claim Generation Methods

        protected IEnumerable<Claim> GenerateJwtClaims(JwtSecurityToken accessToken, JwtSecurityToken idToken,
            JwtSecurityToken refreshToken)
        {
            // Add generic claims
            yield return new Claim(Constants.ClaimTypes.AuthenticationType, _parameters.AuthenticationType);
            yield return new Claim(Constants.ClaimTypes.Version, Global.GetVersion());

            // Save the recieved tokens as claims
            if (_idToken != null)
                yield return new Claim(Constants.ClaimTypes.IdToken, _idToken.RawData);
            if (_accessToken != null)
                yield return new Claim(Constants.ClaimTypes.AccessToken, _accessToken.RawData);
            if (_refreshToken != null)
                yield return new Claim(Constants.ClaimTypes.RefreshToken, _refreshToken.RawData);

            // Add OIDC token claims
            var jsonId = _parameters.ClientId;
            if (_idToken != null)
                foreach (
                    var claim in ProcessOidcToken(idToken.GetPayloadJObject(), ClaimMappings.IdTokenMappings, jsonId))
                    yield return claim;
            if (_accessToken != null)
                foreach (
                    var claim in
                        ProcessOidcToken(accessToken.GetPayloadJObject(), ClaimMappings.AccessTokenMappings, jsonId)
                    )
                    yield return claim;
            if (_refreshToken != null)
                foreach (
                    var claim in
                        ProcessOidcToken(refreshToken.GetPayloadJObject(), ClaimMappings.RefreshTokenMappings, jsonId))
                    yield return claim;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static IEnumerable<Claim> ProcessOidcToken(JObject webToken, IEnumerable<ClaimLookup> claimMappings,
            string jsonId)
        {
            // Process claim mappings
            return claimMappings.SelectMany(lookupClaim => lookupClaim.ProcessClaimLookup(webToken, jsonId));
        }

        #endregion

        #region Private Methods

        private IEnumerable<Claim> GetCurrentClaims()
        {
            return _kcClaims.Concat(_userClaims);
        }

        private async Task<IEnumerable<Claim>> GetClaimsAsync()
        {
            await _refreshLock.WaitAsync();
            try
            {
                // Check to update cached claims
                if (_kcClaims == null || _accessToken.ValidTo <= DateTime.Now)
                {
                    // Validate refresh token expiration
                    if (_refreshToken.ValidTo <= DateTime.Now)
                        throw new Exception("Both the access token and the refresh token have expired");

                    // Load new identity from token endpoint via refresh token
                    var responseMessage =
                        await new RefreshAccessTokenMessage(_parameters, _refreshToken.RawData).ExecuteAsync();
                    ImportTokenResponse(responseMessage);
                }

                return GetCurrentClaims();
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        #endregion
    }
}