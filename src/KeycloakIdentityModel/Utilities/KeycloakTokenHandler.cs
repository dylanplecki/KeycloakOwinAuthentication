using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Threading.Tasks;
using KeycloakIdentityModel.Models.Configuration;
using Microsoft.IdentityModel;

namespace KeycloakIdentityModel.Utilities
{
    internal class KeycloakTokenHandler : JwtSecurityTokenHandler
    {
        public static async Task<SecurityToken> ValidateTokenRemote(string jwt, IKeycloakParameters options)
        {
            var uriManager = await OidcDataManager.GetCachedContextAsync(options);
            return await ValidateTokenRemote(jwt, uriManager);
        }

        public static async Task<SecurityToken> ValidateTokenRemote(string jwt, OidcDataManager uriManager)
        {
            // This should really only be used on access tokens...
            var uri = new Uri(uriManager.TokenValidationEndpoint, "?access_token=" + jwt);
            try
            {
                var client = new HttpClient();
                var response = await client.GetAsync(uri);
                if (!response.IsSuccessStatusCode) throw new Exception();
                return new JwtSecurityToken(jwt); // TODO: Get this from returned JSON
            }
            catch (Exception)
            {
                throw new SecurityTokenValidationException("Remote Token Validation Failed");
            }
        }

        public bool TryValidateToken(string jwt, IKeycloakParameters options, OidcDataManager uriManager, out SecurityToken rToken)
        {
            try
            {
                rToken = ValidateToken(jwt, options, uriManager);
                return true;
            }
            catch (Exception)
            {
                rToken = null;
                return false;
            }
        }

        public async Task<SecurityToken> ValidateTokenAsync(string jwt, IKeycloakParameters options)
        {
            var uriManager = await OidcDataManager.GetCachedContextAsync(options);
            return ValidateToken(jwt, options, uriManager);
        }

        public SecurityToken ValidateToken(string jwt, IKeycloakParameters options, OidcDataManager uriManager)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuer = !options.DisableIssuerValidation,
                ValidateAudience = !options.DisableAudienceValidation,
                ValidateIssuerSigningKey = !options.DisableTokenSignatureValidation,
                RequireSignedTokens = !options.AllowUnsignedTokens,
                ValidIssuer = uriManager.GetIssuer(),
                ClockSkew = options.TokenClockSkew,
                ValidAudiences = new List<string> {"null", options.ClientId},
                IssuerSigningTokens = uriManager.GetJsonWebKeys().GetSigningTokens(),
                AuthenticationType = options.AuthenticationType // Not used
            };

            return ValidateToken(jwt, tokenValidationParameters);
        }

        protected bool TryValidateToken(string securityToken, TokenValidationParameters validationParameters,
            out SecurityToken rToken)
        {
            try
            {
                rToken = ValidateToken(securityToken, validationParameters);
                return true;
            }
            catch (Exception)
            {
                rToken = null;
                return false;
            }
        }

        protected SecurityToken ValidateToken(string securityToken, TokenValidationParameters validationParameters)
        {
            ////////////////////////////////
            // Copied from MS Source Code //
            ////////////////////////////////

            if (string.IsNullOrWhiteSpace(securityToken))
            {
                throw new ArgumentNullException(nameof(securityToken));
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            if (securityToken.Length > MaximumTokenSizeInBytes)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10209,
                    securityToken.Length, MaximumTokenSizeInBytes));
            }

            var jwt = ValidateSignature(securityToken, validationParameters);

            if (jwt.SigningKey != null)
            {
                ValidateIssuerSecurityKey(jwt.SigningKey, jwt, validationParameters);
            }

            DateTime? notBefore = null;
            if (jwt.Payload.Nbf != null)
            {
                notBefore = jwt.ValidFrom;
            }

            DateTime? expires = null;
            if (jwt.Payload.Exp != null)
            {
                expires = jwt.ValidTo;
            }

            Validators.ValidateTokenReplay(securityToken, expires, validationParameters);
            if (validationParameters.ValidateLifetime)
            {
                if (validationParameters.LifetimeValidator != null)
                {
                    if (!validationParameters.LifetimeValidator(notBefore, expires, jwt, validationParameters))
                    {
                        throw new SecurityTokenInvalidLifetimeException(string.Format(CultureInfo.InvariantCulture,
                            ErrorMessages.IDX10230, jwt));
                    }
                }
                else
                {
                    ValidateLifetime(notBefore, expires, jwt, validationParameters);
                }
            }

            if (validationParameters.ValidateAudience)
            {
                if (validationParameters.AudienceValidator != null)
                {
                    if (!validationParameters.AudienceValidator(jwt.Audiences, jwt, validationParameters))
                    {
                        throw new SecurityTokenInvalidAudienceException(string.Format(CultureInfo.InvariantCulture,
                            ErrorMessages.IDX10231, jwt));
                    }
                }
                else
                {
                    ValidateAudience(jwt.Audiences, jwt, validationParameters);
                }
            }

            var issuer = jwt.Issuer;
            if (validationParameters.ValidateIssuer)
            {
                issuer = validationParameters.IssuerValidator != null
                    ? validationParameters.IssuerValidator(issuer, jwt, validationParameters)
                    : ValidateIssuer(issuer, jwt, validationParameters);
            }

            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwt.Actor))
            {
                SecurityToken actor;
                ValidateToken(jwt.Actor, validationParameters, out actor);
            }

            return jwt;
        }
    }
}