using System.Collections.Concurrent;
using Owin.Security.Keycloak.Utilities.Caching;

namespace Owin.Security.Keycloak
{
    internal static class Global
    {
        public static StateCache StateCache { get; } = new StateCache();

        public static ConcurrentDictionary<string, KeycloakAuthenticationOptions> KeycloakOptionStore { get; } =
            new ConcurrentDictionary<string, KeycloakAuthenticationOptions>();
    }
}
