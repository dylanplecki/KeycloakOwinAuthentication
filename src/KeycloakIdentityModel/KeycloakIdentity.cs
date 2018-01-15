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
            ValidateParameters(parameters);
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
        ///     Gets a value that indicates whether the identity has been updated since its instantiation
        /// </summary>
        public bool IsTouched { get; private set; }

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
            if (claim == null) throw new ArgumentNullException(nameof(claim));
            _userClaims.Add(claim);
        }

        /// <summary>
        ///     Adds a list of claims to this claims identity
        /// </summary>
        /// <param name="claims"></param>
        [SecurityCritical]
        public override void AddClaims(IEnumerable<Claim> claims)
        {
            if (claims == null) throw new ArgumentNullException(nameof(claims));
            _userClaims.AddRange(claims);
        }

        /// <summary>
        ///     Attempts to remove a claim from the claims identity
        /// </summary>
        /// <param name="claim"></param>
        [SecurityCritical]
        public override void RemoveClaim(Claim claim)
        {
            if (claim == null) throw new ArgumentNullException(nameof(claim));
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
            if (claim == null) throw new ArgumentNullException(nameof(claim));
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
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (identity == null) throw new ArgumentNullException(nameof(identity));
            return ConvertFromClaimsAsync(parameters, identity.Claims);
        }

        /// <summary>
        ///     Converts a keycloak-generated claims list into a Keycloak identity
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="claims"></param>
        /// <returns></returns>
        public static Task<KeycloakIdentity> ConvertFromClaimsAsync(IKeycloakParameters parameters,
            IEnumerable<Claim> claims)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (claims == null) throw new ArgumentNullException(nameof(claims));

            var claimLookup = claims.ToLookup(c => c.Type, c => c.Value);
            var idToken = claimLookup[Constants.ClaimTypes.IdToken].FirstOrDefault();
            var accessToken = claimLookup[Constants.ClaimTypes.AccessToken].FirstOrDefault();
            var refreshToken = claimLookup[Constants.ClaimTypes.RefreshToken].FirstOrDefault();

            return ConvertFromJwtAsync(parameters, accessToken, refreshToken, idToken);
        }

        /// <summary>
        ///     Converts a JWT token-response endpoint message into a Keycloak identity
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="message"></param>
        /// <returns></returns>
        public static Task<KeycloakIdentity> ConvertFromTokenResponseAsync(IKeycloakParameters parameters,
            TokenResponse message)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (message == null) throw new ArgumentNullException(nameof(message));
            return ConvertFromJwtAsync(parameters, message.AccessToken, message.RefreshToken, message.IdToken);
        }

        /// <summary>
        ///     Converts a JWT token-response endpoint message into a Keycloak identity
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="response"></param>
        /// <param name="baseUri"></param>
        /// <returns></returns>
        public static async Task<KeycloakIdentity> ConvertFromAuthResponseAsync(IKeycloakParameters parameters,
            AuthorizationResponse response, Uri baseUri)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (response == null) throw new ArgumentNullException(nameof(response));
            if (baseUri == null) throw new ArgumentNullException(nameof(baseUri));

            response.ThrowIfError();
            var message = new RequestAccessTokenMessage(baseUri, parameters, response);
            return await ConvertFromTokenResponseAsync(parameters, await message.ExecuteAsync());
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
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (accessToken == null) throw new ArgumentNullException(nameof(accessToken));

            var kcIdentity = new KeycloakIdentity(parameters);
            try
            {
                await kcIdentity.CopyFromJwt(accessToken, refreshToken, idToken);
            }
            catch (SecurityTokenExpiredException)
            {
                // Load new identity from token endpoint via refresh token (if possible)
                await kcIdentity.RefreshIdentity(refreshToken);
            }
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
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (baseUri == null) throw new ArgumentNullException(nameof(baseUri));

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
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (baseUri == null) throw new ArgumentNullException(nameof(baseUri));

            return (await OidcDataManager.GetCachedContextAsync(parameters)).GetCallbackUri(baseUri);
        }

        /// <summary>
        ///     Generates the OpenID Connect compliant Keycloak logout URL
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="baseUri"></param>
        /// <param name="redirectUrl"></param>
        /// <returns></returns>
        public static async Task<Uri> GenerateLogoutUriAsync(IKeycloakParameters parameters, Uri baseUri,
            string redirectUrl = null)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));
            if (baseUri == null) throw new ArgumentNullException(nameof(baseUri));

            // Generate logout URI and data
            var uriManager = await OidcDataManager.GetCachedContextAsync(parameters);
            var logoutParams = uriManager.BuildEndSessionEndpointContent(baseUri, null, redirectUrl);
            var logoutUrl = uriManager.GetEndSessionEndpoint();

            // Return logout URI
            var logoutQueryString = await logoutParams.ReadAsStringAsync();
            return new Uri(logoutUrl + (!string.IsNullOrEmpty(logoutQueryString) ? "?" + logoutQueryString : ""));
        }

        /// <summary>
        ///     Trys to validate an IKeycloakParameters object for completeness and correctness
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static bool TryValidateParameters(IKeycloakParameters parameters)
        {
            try
            {
                ValidateParameters(parameters);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        ///     Validates an IKeycloakParameters object for completeness and correctness
        /// </summary>
        /// <param name="parameters"></param>
        /// <returns></returns>
        public static void ValidateParameters(IKeycloakParameters parameters)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            // Verify required parameters
            if (parameters.KeycloakUrl == null)
                throw new ArgumentNullException(nameof(parameters.KeycloakUrl));
            if (parameters.Realm == null)
                throw new ArgumentNullException(nameof(parameters.Realm));

            // Set default parameters
            if (string.IsNullOrWhiteSpace(parameters.ResponseType))
                throw new ArgumentNullException(nameof(parameters.ResponseType));
            if (string.IsNullOrWhiteSpace(parameters.Scope))
                throw new ArgumentNullException(nameof(parameters.Scope));
            if (string.IsNullOrWhiteSpace(parameters.CallbackPath))
                throw new ArgumentNullException(nameof(parameters.CallbackPath));

            // Validate other parameters
            if (!Uri.IsWellFormedUriString(parameters.KeycloakUrl, UriKind.Absolute))
                throw new ArgumentException(nameof(parameters.KeycloakUrl));
            if (!Uri.IsWellFormedUriString(parameters.CallbackPath, UriKind.Relative) &&
                parameters.CallbackPath != Constants.KeycloakParameters.NoCallbackUri)
                throw new ArgumentException(nameof(parameters.CallbackPath));
            if (parameters.PostLogoutRedirectUrl != null &&
                !Uri.IsWellFormedUriString(parameters.PostLogoutRedirectUrl, UriKind.RelativeOrAbsolute))
                throw new ArgumentException(nameof(parameters.PostLogoutRedirectUrl));

            // Attempt to refresh OIDC metadata from endpoint (on separate thread)
            try
            {
                Task.Run(() => OidcDataManager.GetCachedContextAsync(parameters)).Wait();
            }
            catch (Exception exception)
            {
                throw new ArgumentException("Invalid Keycloak server parameters specified: See inner for server error",
                    exception);
            }
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
                // Check to update cached claims, but not if refresh token is missing (as in bearer mode)
                if ((_kcClaims == null || _accessToken.ValidTo <= DateTime.UtcNow) && _refreshToken != null)
                {
                    // Validate refresh token expiration
                    if (_refreshToken.ValidTo <= DateTime.UtcNow)
                        throw new Exception("Both the access token and the refresh token have expired");

                    // Load new identity from token endpoint via refresh token
                    await RefreshIdentity(_refreshToken.RawData);
                }

                return GetCurrentClaims();
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        protected async Task CopyFromJwt(string accessToken, string refreshToken = null, string idToken = null)
        {
            if (accessToken == null) throw new ArgumentException(nameof(accessToken));

            // Validate JWTs provided
            var tokenHandler = new KeycloakTokenHandler();
            var uriManager = await OidcDataManager.GetCachedContextAsync(_parameters);

            SecurityToken accessSecurityToken, idSecurityToken = null, refreshSecurityToken = null;

            if (_parameters.UseRemoteTokenValidation)
            {
                accessSecurityToken = await KeycloakTokenHandler.ValidateTokenRemote(accessToken, uriManager);
            }
            else
            {
                accessSecurityToken = tokenHandler.ValidateToken(accessToken, _parameters, uriManager);
            }

            // Double-check
            if (accessSecurityToken == null)
                throw new Exception("Internal error: Invalid access token; valid required");

            if (idToken != null)
                idSecurityToken = tokenHandler.ValidateToken(idToken, _parameters, uriManager);
            if (refreshToken != null)
                refreshSecurityToken = tokenHandler.ValidateToken(refreshToken, _parameters, uriManager);

            // Save to this object
            // TODO: Convert to MS claims parsing in token handler
            _kcClaims = GenerateJwtClaims(accessSecurityToken as JwtSecurityToken, idSecurityToken as JwtSecurityToken,
                refreshSecurityToken as JwtSecurityToken);
            _idToken = idSecurityToken as JwtSecurityToken;
            _accessToken = accessSecurityToken as JwtSecurityToken;
            _refreshToken = refreshSecurityToken as JwtSecurityToken;
        }

        protected async Task RefreshIdentity(string refreshToken)
        {
            var respMessage =
                        await new RefreshAccessTokenMessage(_parameters, refreshToken).ExecuteAsync();
            await CopyFromJwt(respMessage.AccessToken, respMessage.RefreshToken, respMessage.IdToken);
            IsTouched = true;
        }

        #endregion
    }
}