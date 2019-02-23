using System;

namespace RevStackCore.Identity
{
    public class IdentityUserRole : IdentityUserRole<string>
    {
        public IdentityUserRole()
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    public class IdentityUserRole<TKey> : IIdentityUserRole<TKey>
    {
        public virtual TKey Id { get; set; }
        public virtual TKey UserId { get; set; }
        public virtual string RoleId { get; set; }
    }
}
