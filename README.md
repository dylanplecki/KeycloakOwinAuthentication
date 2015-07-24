# Keycloak OWIN Authentication
###### Owin.Security.Keycloak - OWIN Authentication Middleware for ASP.NET Web Applications
-------------------------------------------------------------------------------------------

This project is an OWIN middleware designed for connecting ASP.NET web applications to remote
authentication servers via the [OpenID Connect](http://openid.net/) protocol (based on [OAuth 2.0](http://oauth.net/2/)).
It's initial design came from the shortcomings of Microsoft's
[OpenIdConnectAuthentication](https://msdn.microsoft.com/en-us/library/owin.openidconnectauthenticationextensions.aspx)
library, which only includes support for OIDC hybrid and implicit flows.

## Installation

The project can be installed via the official NuGet package `Owin.Security.Keycloak` by the integrated NuGet package manager or at the NuGet Gallery [project website](https://www.nuget.org/packages/Owin.Security.Keycloak).

Required packages for hosting on ASP.NET:
- `Microsoft.Owin.Host.SystemWeb`
- `Microsoft.Owin.Security.Cookies` (or an equivalent middleware)

The source code can be found at the project's [GitHub repository](https://github.com/dylanplecki/KeycloakOwinAuthentication).

## Limitations

This project is still under its initial development phase, so many planned features may not yet be implemented.

- It currently only supports OIDC Authorization Code flow.
- It does not support token validation via signing certificates.
- It is not a full implementation of the OpenID Connect Core 1.0 specification.

## Usage

Basic usage of this project includes calling the `UseKeycloakAuthentication` extension method from within the web application's OWIN startup class.
The following is a brief example on how to do so:

```c#
// File: Startup.cs

using Microsoft.Owin;
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
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
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
```

## Issues & Requests

Issues, feature requests, and technical help can be found at the project's [issue tracker](https://github.com/dylanplecki/KeycloakOwinAuthentication/issues) on GitHub.
