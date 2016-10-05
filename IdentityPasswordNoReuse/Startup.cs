using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(IdentityPasswordNoReuse.Startup))]
namespace IdentityPasswordNoReuse
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
