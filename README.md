# Keycloak OWIN Authentication [![Build status](https://ci.appveyor.com/api/projects/status/xf1kvor22ya99h6w?svg=true)](https://ci.appveyor.com/project/DylanPlecki/keycloakowinauthentication)
###### Owin.Security.Keycloak - OWIN Authentication Middleware for C# Applications
----------------------------------------------------------------------------------

From [Keycloak's Website](http://keycloak.jboss.org/):
> Keycloak is an integrated SSO and IDM for browser apps and RESTful web services, built on top of OAuth 2.0, OpenID Connect, JSON Web Tokens (JWT) and SAML 2.0 specifications. Keycloak has tight integration with a variety of platforms and has an HTTP security proxy service where we don't have tight integration.

This project is an unofficial Keycloak connector for C#. It is designed as an OWIN authentication middleware component, and can import user data, including roles and authorization information, into the OWIN pipeline for use in ASP.NET, WPF, and any other C# application.

## Installation

The project can be installed via the official NuGet package `Owin.Security.Keycloak` by the integrated NuGet package manager or at the NuGet Gallery [project website](https://www.nuget.org/packages/Owin.Security.Keycloak).

Required package(s) for hosting on ASP.NET / IIS:
- `Microsoft.Owin.Host.SystemWeb`

Recommended package(s) for hosting on ASP.NET / IIS:
- `Microsoft.Owin.Security.Cookies`

The source code can be found at the project's [GitHub repository](https://github.com/dylanplecki/KeycloakOwinAuthentication).

## Usage

Basic usage of this project includes calling the `UseKeycloakAuthentication` extension method from within the web application's OWIN startup class.
The following is a brief example on how to do so using the `Microsoft.Owin.Host.SystemWeb` and `Microsoft.Owin.Security.Cookies` packages:

```c#
// File: Startup.cs

using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Owin.Security.Keycloak;

[assembly: OwinStartup(typeof (Sample.KeycloakAuth.Startup))]

namespace Sample.KeycloakAuth
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
```

## Configuration

All configuration is done via the `KeycloakAuthenticationOptions` object passed on OWIN startup. The available options are detailed below:

_Note: If using more than one Keycloak authentication module, you must define unique `AuthenticationType` attributes for each `KeycloakAuthenticationOptions` object._

```c#
/// <summary>
///     Defines the entire URL to the Keycloak instance
/// </summary>
/// <remarks>
///     - By default, keycloak is deployed to the /auth submodule
///     on the webserver, which must be included in this URL
/// </remarks>
public string KeycloakUrl { get; set; }

/// <summary>
///     The Keycloak realm on which the client is located
/// </summary>
public string Realm { get; set; }

/// <summary>
///     The client ID to use for the application
/// </summary>
public string ClientId { get; set; }

/// <summary>
///     OPTIONAL: The client secret to use for the application
/// </summary>
/// <remarks>
///     - Not required for public clients
///     - Default: None
/// </remarks>
public string ClientSecret { get; set; }

/// <summary>
///     OPTIONAL: The OpenID scopes to request when authenticating a user
/// </summary>
/// <remarks>
///     - All scopes should be space-delimited in a single string
///     - Default: "openid"
/// </remarks>
public string Scope { get; set; }

/// <summary>
///     OPTIONAL: Choose a default identity provider to use for the application
/// </summary>
/// <remarks>
///     - The value here must be a valid IDP ID in the specified Keycloak realm
///     - Only this chosen IDP may be used with this application
///     - The Keycloak login page will not be shown when this option is non-empty
///     - Default: None
/// </remarks>
public string IdentityProvider { get; set; }

/// <summary>
///     OPTIONAL: The absolute or relative URL for users to be redirected to after logout
/// </summary>
/// <remarks>
///     - Default: Application base URL
/// </remarks>
public string PostLogoutRedirectUrl { get; set; }

/// <summary>
///     OPTIONAL: Defines the virtual root of the current application
/// </summary>
/// <remarks>
///     - For instance, if using a virtual directory in IIS such as "/secure",
///     this option would be "/secure"
///     - Default: "/"
/// </remarks>
public string VirtualDirectory { get; set; }

/// <summary>
///     OPTIONAL: Whether to use the Web API authentication mode via bearer tokens
///     in the authentication header instead of interactive logins
/// </summary>
/// <remarks>
///     - This will auto-enable 'EnableBearerTokenAuth' and 'ForceBearerTokenAuth',
///     both of which cannot be switched off in this mode
///     - Default: False
/// </remarks>
public bool EnableWebApiMode { get; set; } = false;

/// <summary>
///     OPTIONAL: The persistent sign-in mechanism used by the extension
/// </summary>
/// <remarks>
///     - Required for any session-based usage
///     - Default: Null
/// </remarks>
public string SignInAsAuthenticationType { get; set; }

/// <summary>
///     OPTIONAL.ADV: Save access and ID tokens as user claims
/// </summary>
/// <remarks>
///     - Forced enabled when using 'AutoTokenRefresh'
///     - Default: True
/// </remarks>
public bool SaveTokensAsClaims { get; set; } = true;

/// <summary>
///     OPTIONAL.ADV: Allow authentication via the bearer token authorization header
/// </summary>
/// <remarks>
///     - Forced enabled when using 'ForceBearerTokenAuth'
///     - Default: False
/// </remarks>
public bool EnableBearerTokenAuth { get; set; } = false;

/// <summary>
///     OPTIONAL.ADV: Force all authentication to be done via 'BearerTokenAuth' (above)
/// </summary>
/// <remarks>
///     - If an inbound request does not present a valid bearer token,
///     a 403 error will be issued.
///     - Default: False
/// </remarks>
public bool ForceBearerTokenAuth { get; set; } = false;

/// <summary>
///     OPTIONAL.ADV: Automatically refresh user tokens upon expiration
/// </summary>
/// <remarks>
///     - Default: True
/// </remarks>
public bool AutoTokenRefresh { get; set; } = true;

/// <summary>
///     OPTIONAL.ADV: Whether to check for valid token signatures before accepting
/// </summary>
/// <remarks>
///     - If enabled, this will create a MASSIVE security hole
///     - Default: False
/// </remarks>
public bool DisableTokenSignatureValidation { get; set; } = false;

/// <summary>
///     OPTIONAL.ADV: Whether to allow the extension to accept unsigned tokens
/// </summary>
/// <remarks>
///     - If enabled, this will create a MASSIVE security hole
///     - Default: False
/// </remarks>
public bool AllowUnsignedTokens { get; set; } = false;

/// <summary>
///     OPTIONAL.ADV: Whether to disable the validation of the issuer of any returned token
/// </summary>
/// <remarks>
///     - Default: False
/// </remarks>
public bool DisableIssuerValidation { get; set; } = false;

/// <summary>
///     OPTIONAL.ADV: Whether to disable the validation of the audience (app) of any returned token
/// </summary>
/// <remarks>
///     - Default: False
/// </remarks>
public bool DisableAudienceValidation { get; set; } = false;

/// <summary>
///     OPTIONAL.ADV: The maximum grace time span for expired tokens to be accepted
/// </summary>
/// <remarks>
///     - Default: 5 seconds
/// </remarks>
public TimeSpan TokenClockSkew { get; set; } = TimeSpan.FromSeconds(5);

/// <summary>
///     OPTIONAL.ADV: Whether to enable token validation via the Keycloak server
/// </summary>
/// <remarks>
///     - Enabling this option will require an HTTP call to the Keycloak server
///     on every request with a bearer token, or when new tokens are requested
///     - Enabling this option will also allow changes on the Keycloak server to
///     be seen by the end user immediately, ie. assigning a new role to a user
///     - Default: false
/// </remarks>
public bool UseRemoteTokenValidation { get; set; } = false;

/// <summary>
///     OPTIONAL.ADV: The interval in seconds for the OIDC metadata to refresh
/// </summary>
/// <remarks>
///     - User -1 for no refreshing, and 0 to always refresh
///     - Default: 3600 seconds (60 minutes)
/// </remarks>
public int MetadataRefreshInterval { get; set; } = 3600;
```

## Issues & Requests

Issues, feature requests, and technical help can be found at the project's [issue tracker](https://github.com/dylanplecki/KeycloakOwinAuthentication/issues) on GitHub.
