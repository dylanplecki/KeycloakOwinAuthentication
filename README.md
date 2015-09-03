# Keycloak OWIN Authentication
###### Owin.Security.Keycloak - OWIN Authentication Middleware for C# Applications
----------------------------------------------------------------------------------

From [Keycloak's Website](http://keycloak.jboss.org/):
> Keycloak is an integrated SSO and IDM for browser apps and RESTful web services, built on top of OAuth 2.0, OpenID Connect, JSON Web Tokens (JWT) and SAML 2.0 specifications. Keycloak has tight integration with a variety of platforms and has an HTTP security proxy service where we don't have tight integration.

This project is an unofficial Keycloak connector for C#. It is designed as an OWIN authentication middleware component, and can import user data, including roles and authorization information, into the OWIN pipeline for use in ASP.NET, WPF, and any other C# application.

## Installation

The project can be installed via the official NuGet package `Owin.Security.Keycloak` by the integrated NuGet package manager or at the NuGet Gallery [project website](https://www.nuget.org/packages/Owin.Security.Keycloak).

Required package(s) for hosting on ASP.NET / IIS:
- `Microsoft.Owin.Host.SystemWeb`

The source code can be found at the project's [GitHub repository](https://github.com/dylanplecki/KeycloakOwinAuthentication).

## Usage

Basic usage of this project includes calling the `UseKeycloakAuthentication` extension method from within the web application's OWIN startup class.
The following is a brief example on how to do so:

```c#
// File: Startup.cs

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
                ClientId = "sample_keycloakAuth",
                ClientSecret = "3a06aae9-53d2-43a9-ba00-f188ff7b6d99",
                KeycloakUrl = "http://keycloak.site.com/auth",
                PostLogoutRedirectUrl = "http://keycloaksampleapp.site.com/login"
            });
        }
    }
}
```

## Issues & Requests

Issues, feature requests, and technical help can be found at the project's [issue tracker](https://github.com/dylanplecki/KeycloakOwinAuthentication/issues) on GitHub.
