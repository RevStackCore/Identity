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
        public virtual TKey Id { get; set; }
        public virtual TKey RoleId { get; set; }
        public virtual string ClaimType { get; set;  }
        public virtual string ClaimValue { get; set; }

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
