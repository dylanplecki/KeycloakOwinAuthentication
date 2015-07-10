using Microsoft.Owin.Security;

namespace Boca
{
    public class BocAuthenticationOptions : AuthenticationOptions
    {
        private const string DefaultAuthenticationType = "BocAuthenticationOptions";

        public string Authority { get; set; }
        public string MetadataAddress { get; set; }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        public string Scope { get; set; }
        public string Resource { get; set; }
        public string ResponseType { get; set; }

        public string CallbackPath { get; set; }
        public string PostLogoutRedirectUri { get; set; }

        public BocAuthenticationOptions()
            : base(DefaultAuthenticationType)
        {
        }
    }
}
