using System;
using Newtonsoft.Json;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak
{
    internal static class KeycloakOptionsExtension
    {
        internal static bool TryDeserialize(string content, out IKeycloakOptions options)
        {
            try
            {
                options = JsonConvert.DeserializeObject<KeycloakAuthenticationOptions>(content);
                return true;
            }
            catch (Exception)
            {
                options = null;
                return false;
            }
        }

        internal static string Serialize(this IKeycloakOptions options)
        {
            return JsonConvert.SerializeObject(options,
                new JsonSerializerSettings
                {
                    ContractResolver = new InterfaceContractResolver(typeof (IKeycloakOptions))
                });
        }
    }
}
