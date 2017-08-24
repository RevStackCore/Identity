using System;
using RevStackCore.Pattern;
using Microsoft.AspNetCore.Identity;

namespace RevStackCore.Identity
{
    public interface IIdentityRole<TKey> : IEntity<TKey>
    {
        new TKey Id { get; set; }
        string Name { get; set; }
        string NormalizedName { get; set; }
    }
}
