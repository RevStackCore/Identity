using System;

namespace RevStackCore.Identity
{
    public class IdentityUserClaim: IdentityUserClaim<string>
    {
        public IdentityUserClaim()
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    public class IdentityUserClaim<TKey> : IIdentityUserClaim<TKey>
    {
        public virtual TKey Id { get; set; }
        public virtual TKey UserId { get; set; }
        public virtual string ClaimType { get; set; }
        public virtual string ClaimValue { get; set; }
    }
}
