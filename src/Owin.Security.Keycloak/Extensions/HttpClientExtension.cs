using System.Net.Http;
using System.Net.Http.Headers;

namespace Owin.Security.Keycloak
{
    internal static class HttpClientExtension
    {
        public static void SetToken(this HttpClient client, string scheme, string token)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(scheme, token);
        }

        public static void SetBearerToken(this HttpClient client, string token)
        {
            client.SetToken("Bearer", token);
        }
    }
}