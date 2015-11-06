using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using KeycloakIdentityModel.Extensions;
using Newtonsoft.Json.Linq;

namespace KeycloakIdentityModel.Utilities.ClaimMapping
{
    internal static class ClaimMappings
    {
        public static IEnumerable<ClaimLookup> AccessTokenMappings { get; } = new List<ClaimLookup>
        {
            new ClaimLookup
            {
                ClaimName = Constants.ClaimTypes.Audience,
                JSelectQuery = "aud"
            },
            new ClaimLookup
            {
                ClaimName = Constants.ClaimTypes.Issuer,
                JSelectQuery = "iss"
            },
            new ClaimLookup
            {
                ClaimName = Constants.ClaimTypes.IssuedAt,
                JSelectQuery = "iat",
                Transformation =
                    token => ((token.Value<double?>() ?? 1) - 1).ToDateTime().ToString(CultureInfo.InvariantCulture)
            },
            new ClaimLookup
            {
                ClaimName = Constants.ClaimTypes.AccessTokenExpiration,
                JSelectQuery = "exp",
                Transformation =
                    token => ((token.Value<double?>() ?? 1) - 1).ToDateTime().ToString(CultureInfo.InvariantCulture)
            },
            new ClaimLookup
            {
                ClaimName = Constants.ClaimTypes.SubjectId,
                JSelectQuery = "sub"
            },
            new ClaimLookup
            {
                ClaimName = ClaimTypes.Name,
                JSelectQuery = "preferred_username"
            },
            new ClaimLookup
            {
                ClaimName = ClaimTypes.GivenName,
                JSelectQuery = "given_name"
            },
            new ClaimLookup
            {
                ClaimName = ClaimTypes.Surname,
                JSelectQuery = "family_name"
            },
            new ClaimLookup
            {
                ClaimName = ClaimTypes.Email,
                JSelectQuery = "email"
            },
            new ClaimLookup
            {
                ClaimName = ClaimTypes.Role,
                JSelectQuery = "resource_access.{gid}.roles"
            }
        };

        public static IEnumerable<ClaimLookup> IdTokenMappings { get; } = new List<ClaimLookup>();

        public static IEnumerable<ClaimLookup> RefreshTokenMappings { get; } = new List<ClaimLookup>
        {
            new ClaimLookup
            {
                ClaimName = Constants.ClaimTypes.RefreshTokenExpiration,
                JSelectQuery = "exp",
                Transformation =
                    token => ((token.Value<double?>() ?? 1) - 1).ToDateTime().ToString(CultureInfo.InvariantCulture)
            }
        };
    }
}