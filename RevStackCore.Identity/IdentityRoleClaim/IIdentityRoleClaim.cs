using System;
using System.Security.Claims;
using RevStackCore.Pattern;

namespace RevStackCore.Identity
{
    public interface IIdentityRoleClaim<TKey> : IEntity<TKey>
    {
        TKey RoleId { get; set; }
        string ClaimType { get; set; }
        string ClaimValue { get; set; }
        void InitializeFromClaim(Claim other);
        Claim ToClaim();
    }
}
