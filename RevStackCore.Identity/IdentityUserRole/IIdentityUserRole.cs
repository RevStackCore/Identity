using System;
using RevStackCore.Pattern;

namespace RevStackCore.Identity
{
    public interface IIdentityUserRole<TKey> : IEntity<TKey>
    {
        TKey UserId { get; set; }
        string RoleId { get; set; }
    }
}
