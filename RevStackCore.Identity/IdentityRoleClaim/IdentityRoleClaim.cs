using System;
using System.Security.Claims;

namespace RevStackCore.Identity
{

    public class IdentityRoleClaim : IdentityRoleClaim<string>
    {
		public IdentityRoleClaim()
		{
			Id = Guid.NewGuid().ToString();
		}
    }

    public class IdentityRoleClaim<TKey> : IIdentityRoleClaim<TKey>
    {
        public TKey Id { get; set; }
        public TKey RoleId { get; set; }
        public string ClaimType { get; set;  }
        public string ClaimValue { get; set; }

        public void InitializeFromClaim(Claim other)
        {
            ClaimType = other.Type;
            ClaimValue = other.Value;
        }

        public Claim ToClaim()
        {
            return new Claim(ClaimType, ClaimValue);
           
        }
    }
}
