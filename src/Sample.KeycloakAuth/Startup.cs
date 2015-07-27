using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Keycloak;

[assembly: OwinStartup(typeof(Sample.KeycloakAuth.Startup))]

namespace Sample.KeycloakAuth
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            app.UseKeycloakAuthentication(new KeycloakAuthenticationOptions
            {
                Realm = "master",
                ClientId = "sample_keycloakAuth",
                ClientSecret = "3a06aae9-53d2-43a9-ba00-f188ff7b6d99",
                KeycloakUrl = "http://keycloak.site.com/auth",
            });
        }
    }
}
