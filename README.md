 ASP.Net Identity Password No Reuse
Add "no password reuse" policy to ASP.Net Identity 2.2.1

Prevent users from reusing passwords used the last year.



## Resume
- Add new class PreviousPassword to IdentityModels.cs
- Override ChangePasswordAsync in IdentityCongig.cs
- Override ResetPasswordAsync in IdentityCongig.cs
- Add IsPreviousPassword to IdentityCongig.cs
- Add ApplicationUserStore to IdentityCongig.cs

## How to create the solution

Create a new project. Use ASP.NET WebApplication (.NET Framework)

![Image01](https://github.com/PeterQuistgaard/IdentityPasswordNoReuse/blob/master/Image1.png)

![Image01](https://github.com/PeterQuistgaard/IdentityPasswordNoReuse/blob/master/Image2.png)


## Make some changes in the generated code.

All changes are placed between #region Change and #endregion Change.
There are about 7 places with changes. 



### Web.Config
Change connectionStrings to match your prefered database. 
     
```XML

  <connectionStrings>
   <!-- #region Change -->
    <add name="DefaultConnection" 
         providerName="System.Data.SqlClient" 
         connectionString="Data Source=.\SQLEXPRESS;Initial Catalog=IdentityPasswordNoReuse;Integrated Security=SSPI" />
   <!-- #endregion Change-->      
  </connectionStrings>

```

### Modify class ApplicationUser in IdentityModels 

```C#
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
```


### Add class ApplicationUserStore to IdentityConfig.cs


```C#
#region Change
public class ApplicationUserStore : UserStore<ApplicationUser>
{
    public ApplicationUserStore(DbContext context)
        : base(context)
    {
    }

    public override async Task CreateAsync(ApplicationUser user)
    {
        await base.CreateAsync(user);
        await AddToPreviousPasswordsAsync(user, user.PasswordHash);
    }

    public Task AddToPreviousPasswordsAsync(ApplicationUser user, string password)
    {
        user.PreviousUserPasswords.Add(new PreviousPassword() { UserId = user.Id, PasswordHash = password });
        return UpdateAsync(user);
    }
}
#endregion Change
```


### Modify line in class ApplicationUserManager to use the new ApplicationUserStore  

```C#  
#region Change
       var manager = new ApplicationUserManager(new ApplicationUserStore(context.Get<ApplicationDbContext>()));
    // var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
#endregion Change
```


### Add new class PreviousPassword to IdentityModels.cs

```C#  
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

```


### Override ChangePasswordAsync and ResetPasswordAsync in class ApplicationUserManager in IdentityConfig.cs


```C#
#region Change
public override async Task<IdentityResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
{
    if (await IsPreviousPassword(userId, newPassword))
    {
        return await Task.FromResult(IdentityResult.Failed("Cannot reuse old password"));
    }
    var result = await base.ChangePasswordAsync(userId, currentPassword, newPassword);
    if (result.Succeeded)
    {
        var store = Store as ApplicationUserStore;

        await store.AddToPreviousPasswordsAsync(await FindByIdAsync(userId), PasswordHasher.HashPassword(newPassword));
    }
    return result;
}


public override async Task<IdentityResult> ResetPasswordAsync(string userId, string token, string newPassword)
{
    if (await IsPreviousPassword(userId, newPassword))
    {
        return await Task.FromResult(IdentityResult.Failed("Cannot reuse old password"));
    }
    var result = await base.ResetPasswordAsync(userId, token, newPassword);
    if (result.Succeeded)
    {
        var store = Store as ApplicationUserStore;
        await store.AddToPreviousPasswordsAsync(await FindByIdAsync(userId), PasswordHasher.HashPassword(newPassword));
    }
    return result;
}
#endregion Change
```

### Add IsPreviousPassword to ApplicationUserManager (IdentityConfig.cs)


```C#
#region Change
private async Task<bool> IsPreviousPassword(string userId, string newPassword)
{
    var user = await FindByIdAsync(userId);
    DateTime OneYearAgo = DateTime.UtcNow.AddYears(-1);
    if (user.PreviousUserPasswords.Where(x => x.PasswordChangedDateUtc> OneYearAgo).Select(x => x.PasswordHash)
    .Where(x => PasswordHasher.VerifyHashedPassword(x, newPassword) != PasswordVerificationResult.Failed).
    Any())
    {
        return true;
    }
    return false;
}
#endregion Change
```



