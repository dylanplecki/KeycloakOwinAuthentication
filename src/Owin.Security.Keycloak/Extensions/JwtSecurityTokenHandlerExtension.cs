using System;
using System.Globalization;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel;

namespace Owin.Security.Keycloak
{
    internal static class JwtSecurityTokenHandlerExtension
    {
        public static bool ValidateToken(this JwtSecurityTokenHandler tokenHandler, string securityToken,
            TokenValidationParameters validationParameters)
        {
            ////////////////////////////////
            // Copied from MS Source Code //
            ////////////////////////////////

            // TODO: http://www.codeproject.com/Articles/80343/Accessing-private-members.aspx

            if (string.IsNullOrWhiteSpace(securityToken))
            {
                throw new ArgumentNullException(nameof(securityToken));
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            if (securityToken.Length > tokenHandler.MaximumTokenSizeInBytes)
            {
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10209,
                    securityToken.Length, tokenHandler.MaximumTokenSizeInBytes));
            }

            JwtSecurityToken jwt = tokenHandler.ValidateSignature(securityToken, validationParameters);

            if (jwt.SigningKey != null)
            {
                tokenHandler.ValidateIssuerSecurityKey(jwt.SigningKey, jwt, validationParameters);
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
                    tokenHandler.ValidateLifetime(notBefore: notBefore, expires: expires, securityToken: jwt,
                        validationParameters: validationParameters);
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
                    tokenHandler.ValidateAudience(jwt.Audiences, jwt, validationParameters);
                }
            }

            var issuer = jwt.Issuer;
            if (validationParameters.ValidateIssuer)
            {
                issuer = validationParameters.IssuerValidator != null
                    ? validationParameters.IssuerValidator(issuer, jwt, validationParameters)
                    : tokenHandler.ValidateIssuer(issuer, jwt, validationParameters);
            }

            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jwt.Actor))
            {
                SecurityToken actor;
                tokenHandler.ValidateToken(jwt.Actor, validationParameters, out actor);
            }

            return true;
        }
    }
}
