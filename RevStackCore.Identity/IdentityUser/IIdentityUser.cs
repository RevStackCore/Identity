using System;
using Microsoft.AspNetCore.Identity;
using RevStackCore.Pattern;

namespace RevStackCore.Identity
{
    public interface IIdentityUser<TKey> : IEntity<TKey>
    {
        new TKey Id { get; set; }
        string Email { get; set; }
        string NormalizedEmail { get; set; }
        bool EmailConfirmed { get; set; }
        string UserName { get; set; }
        string NormalizedUserName { get; set; }
        string PhoneNumber { get; set; }
        bool PhoneNumberConfirmed { get; set; }
        string PasswordHash { get; set; }
        string SecurityStamp { get; set; }
        bool IsLockoutEnabled { get; set; }
        bool IsTwoFactorEnabled { get; set; }
        int AccessFailedCount { get; set; }
        DateTimeOffset? LockoutEndDate { get; set; }
        DateTime SignUpDate { get; set; }
    }
}
