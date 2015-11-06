using System.Collections.Concurrent;
using System.Reflection;
using KeycloakIdentityModel;
using KeycloakIdentityModel.Utilities.Caching;

namespace Owin.Security.Keycloak
{
    internal static class Global
    {
        public static StateCache StateCache { get; } = new StateCache();

        public static ConcurrentDictionary<string, KeycloakAuthenticationOptions> KeycloakOptionStore { get; } =
            new ConcurrentDictionary<string, KeycloakAuthenticationOptions>();
    }
}