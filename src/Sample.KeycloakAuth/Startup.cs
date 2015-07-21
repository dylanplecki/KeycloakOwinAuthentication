using Microsoft.Owin;
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
                ClientId = "owin_ext_test_client",
                ClientSecret = "f48cec95-ba2d-4c13-b85c-292782e48020",
                KeycloakUrl = "http://mdw2k8dazbus01.dow.com:8080/auth",
            });
        }
    }
}
