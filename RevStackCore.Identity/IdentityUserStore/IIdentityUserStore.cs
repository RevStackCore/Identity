using System;
using Microsoft.AspNetCore.Identity;

namespace RevStackCore.Identity
{
    public interface IIdentityUserStore<TUser, TKey> : IUserStore<TUser>, IUserLoginStore<TUser>, IUserClaimStore<TUser>,
       IUserRoleStore<TUser>, IUserPasswordStore<TUser>, IUserSecurityStampStore<TUser>, IUserEmailStore<TUser>,
       IUserPhoneNumberStore<TUser>, IUserLockoutStore<TUser>, IUserTwoFactorStore<TUser>, IUserAuthenticationTokenStore<TUser>,
       IQueryableUserStore<TUser>
       where TUser : class,IIdentityUser<TKey>
    {

    }
}
