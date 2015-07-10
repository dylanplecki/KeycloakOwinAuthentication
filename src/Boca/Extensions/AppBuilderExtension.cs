using Boca.Middleware;
using Owin;

namespace Boca
{
    public static class AppBuilderExtension
    {
        public static IAppBuilder UseBocAuthenticaion(this IAppBuilder app, BocAuthenticationOptions options)
        {
            return app.Use(typeof(BocAuthenticationMiddleware), app, options);
        }
    }
}
