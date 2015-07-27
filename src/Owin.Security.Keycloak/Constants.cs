namespace Owin.Security.Keycloak
{
    internal class Constants
    {
        public static class ClaimTypes
        {
            public const string IdToken = "id_token";
            public const string AccessToken = "access_token";
            public const string RefreshToken = "refresh_token";

            public const string AccessTokenExpiration = "access_token_expiration";
            public const string RefreshTokenExpiration = "refresh_token_expiration";

            public const string KeycloakOptions = "keycloak_auth_options";
        }
    }
}
