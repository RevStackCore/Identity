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
        public TKey Id { get; set; }
        public TKey UserId { get; set; }
        public string ClaimType { get; set; }
        public string ClaimValue { get; set; }
    }
}
