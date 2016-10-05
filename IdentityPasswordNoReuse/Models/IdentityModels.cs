using System.Data.Entity;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using System;
using System.Collections.Generic;

namespace IdentityPasswordNoReuse.Models
{
    // You can add profile data for the user by adding more properties to your ApplicationUser class, please visit http://go.microsoft.com/fwlink/?LinkID=317594 to learn more.
    public class ApplicationUser : IdentityUser
    {
        #region Change
        public ApplicationUser() : base()
        {
            PreviousUserPasswords = new List<PreviousPassword>();
        }
        public virtual IList<PreviousPassword> PreviousUserPasswords { get; set; }

        #endregion Change

        public async Task<ClaimsIdentity> GenerateUserIdentityAsync(UserManager<ApplicationUser> manager)
        {
            // Note the authenticationType must match the one defined in CookieAuthenticationOptions.AuthenticationType
            var userIdentity = await manager.CreateIdentityAsync(this, DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here
            return userIdentity;
        }
    }

    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
        }

        public static ApplicationDbContext Create()
        {
            return new ApplicationDbContext();
        }
    }

    #region Change
    [Table("AspNetUserPreviousPasswords")]
    public class PreviousPassword
    {
        public PreviousPassword()
        {
            PasswordChangedDateUtc = DateTime.UtcNow; ;
        }

        [Key, Column(Order = 0)]
        public string PasswordHash { get; set; }

        public DateTime PasswordChangedDateUtc { get; set; }

        [Key, Column(Order = 1)]
        public string UserId { get; set; }

        public virtual ApplicationUser User { get; set; }
    }
    #endregion Change
}