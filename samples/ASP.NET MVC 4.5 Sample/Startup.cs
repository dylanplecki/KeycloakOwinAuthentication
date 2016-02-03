using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Keycloak;
using SampleKeycloakApp;

[assembly: OwinStartup(typeof(Startup))]

namespace SampleKeycloakApp
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            const string persistentAuthType = "keycloak_cookies"; // Or name it whatever you want

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = persistentAuthType
            });

            // You may also use this method if you have multiple authentication methods below,
            // or if you just like it better:
            app.SetDefaultSignInAsAuthenticationType(persistentAuthType);

            app.UseKeycloakAuthentication(new KeycloakAuthenticationOptions
            {
                Realm = "master",
                ClientId = "sample_keycloakAuth",
                ClientSecret = "3a06aae9-53d2-43a9-ba00-f188ff7b6d99",
                KeycloakUrl = "http://keycloak.site.com/auth",
                SignInAsAuthenticationType = persistentAuthType // Not required with SetDefaultSignInAsAuthenticationType
            });
        }
    }
}