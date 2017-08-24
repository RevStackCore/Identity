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
        public TKey Id { get; set; }
        public TKey UserId { get; set; }
        public string RoleId { get; set; }
    }
}
