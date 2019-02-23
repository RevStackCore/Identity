using System;


namespace RevStackCore.Identity
{
    public class IdentityRole : IdentityRole<string>
    {
        public IdentityRole()
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    public class IdentityRole<TKey> : IIdentityRole<TKey>
    {
        public virtual TKey Id { get; set; }
        public virtual string Name { get; set; }
        public virtual string NormalizedName { get; set; }
        public virtual string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
		
    }
}
