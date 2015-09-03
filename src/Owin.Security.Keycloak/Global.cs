using System.Collections.Concurrent;
using System.Reflection;
using Owin.Security.Keycloak.Internal;

namespace Owin.Security.Keycloak
{
    internal static class Global
    {
        public static StateCache StateCache { get; } = new StateCache();

        public static ConcurrentDictionary<string, KeycloakAuthenticationOptions> KeycloakOptionStore { get; } =
            new ConcurrentDictionary<string, KeycloakAuthenticationOptions>();

        public static string GetVersion()
        {
            return Assembly.GetExecutingAssembly().GetName().Version.ToString();
        }

        public static bool CheckVersion(string version)
        {
            return GetVersion() == version;
        }
    }
}