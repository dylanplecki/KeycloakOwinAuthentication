namespace Owin.Security.Keycloak
{
    internal static class Constants
    {
        public static class ClaimTypes
        {
            public const string IdToken = "id_token";
            public const string AccessToken = "access_token";
            public const string RefreshToken = "refresh_token";

            public const string AccessTokenExpiration = "access_token_expiration";
            public const string RefreshTokenExpiration = "refresh_token_expiration";

            public const string AuthenticationType = "keycloak_authentication_type";
        }

        public static class CacheTypes
        {
            public const string ReturnUri = "returnUri";
            public const string AuthenticationProperties = "authProperties";
        }
    }
}
