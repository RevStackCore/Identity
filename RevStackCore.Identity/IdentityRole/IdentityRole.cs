using System;


namespace RevStackCore.Identity
{
    public class IdentityRole : IIdentityRole<string>
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string NormalizedName { get; set; }
        public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

        public IdentityRole()
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    public class IdentityRole<TKey> : IIdentityRole<TKey>
    {
        public TKey Id { get; set; }
        public string Name { get; set; }
        public string NormalizedName { get; set; }
        public string ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();
		
    }
}
