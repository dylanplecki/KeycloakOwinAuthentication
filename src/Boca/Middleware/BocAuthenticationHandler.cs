using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace Boca.Middleware
{
    internal class BocAuthenticationHandler : AuthenticationHandler<BocAuthenticationOptions>
    {
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            
        }

        public override Task<bool> InvokeAsync()
        {

        }

        protected override Task ApplyResponseGrantAsync()
        {

        }

        protected override Task ApplyResponseChallengeAsync()
        {

        }
    }
}
