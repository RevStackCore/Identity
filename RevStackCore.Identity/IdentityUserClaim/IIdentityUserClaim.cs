using System;
using RevStackCore.Pattern;

namespace RevStackCore.Identity
{
    public interface IIdentityUserClaim<TKey> : IEntity<TKey>
    {
        TKey UserId { get; set; }
        string ClaimType { get; set; }
        string ClaimValue { get; set; }
    }
}
