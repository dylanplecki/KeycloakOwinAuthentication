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
                KeycloakUrl = "http://keycloak.site.com/auth"
            });
        }
    }
}
```

## Configuration

All configuration is done via the `KeycloakAuthenticationOptions` object passed on OWIN startup. The available options are detailed below:

```c#
/// <summary>
/// Defines the entire URL to the Keycloak instance
/// </summary>
/// <remarks>
///   - By default, keycloak is deployed to the /auth submodule
///     on the webserver, which must be included in this URL
/// </remarks>
public string KeycloakUrl;

/// <summary>
/// The Keycloak realm on which the client is located
/// </summary>
public string Realm;

/// <summary>
/// OPTIONAL: The OpenID scopes to request when authenticating a user
/// </summary>
/// <remarks>
///   - All scopes should be space-delimited in a single string
///   - Default: "openid"
/// </remarks>
public string Scope;

/// <summary>
/// The client ID to use for the application
/// </summary>
public string ClientId;

/// <summary>
/// OPTIONAL: The client secret to use for the application
/// </summary>
/// <remarks>
///   - Not required for public clients
///   - Default: None
/// </remarks>
public string ClientSecret;

/// <summary>
/// OPTIONAL: The absolute URL for users to be redirected to after logout
/// </summary>
/// <remarks>
///   - Default: Base URL
/// </remarks>
public string PostLogoutRedirectUrl;

/// <summary>
/// OPTIONAL: Automatically refresh user tokens upon expiration
/// </summary>
/// <remarks>
///   - Default: True
/// </remarks>
public bool AutoTokenRefresh;

/// <summary>
/// OPTIONAL: Save access and ID tokens as user claims
/// </summary>
/// <remarks>
///   - Forced enabled when using 'AutoTokenRefresh'
///   - Default: True
/// </remarks>
public bool SaveTokensAsClaims;
```

Note: If using more than one Keycloak authentication module, you must define unique `AuthenticationType` attributes for each `KeycloakAuthenticationOptions` object.

## Issues & Requests

Issues, feature requests, and technical help can be found at the project's [issue tracker](https://github.com/dylanplecki/KeycloakOwinAuthentication/issues) on GitHub.
