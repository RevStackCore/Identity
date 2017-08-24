using System;
using RevStackCore.Pattern;

namespace RevStackCore.Identity
{
    public interface IIdentityUserLogin<TKey> : IEntity<TKey>
    {
        string LoginProvider { get; set; }
        string ProviderKey { get; set; }
        string ProviderDisplayName { get; set; }
        TKey UserId { get; set; }
    }
}
