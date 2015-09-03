using Newtonsoft.Json.Linq;

namespace Owin.Security.Keycloak.Internal.ClaimMapping
{
    internal class ClaimLookup
    {
        public delegate string TransformFunc(JToken token);

        public string ClaimName { get; set; }
        public string JSelectQuery { get; set; }
        public bool IsPluralQuery { get; set; }
        public TransformFunc Transformation { get; set; } = token => token.ToString();
    }
}