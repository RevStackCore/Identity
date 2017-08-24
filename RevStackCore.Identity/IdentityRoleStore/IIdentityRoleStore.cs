using System;
using Microsoft.AspNetCore.Identity;

namespace RevStackCore.Identity
{
    public interface IIdentityRoleStore<TRole, TKey> : IRoleStore<TRole> where TRole : class, IIdentityRole<TKey>
    {

    }
}
