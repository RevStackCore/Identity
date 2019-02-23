using System;

namespace RevStackCore.Identity
{
    public class IdentityUserLogin: IdentityUserLogin<string>
    {
        public IdentityUserLogin()
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    public class IdentityUserLogin<TKey> : IIdentityUserLogin<TKey>
    {
        public virtual TKey Id { get; set; }
        public virtual string LoginProvider { get; set; }
        public virtual string ProviderKey { get; set; }
        /// <summary>
		///     Gets or sets the friendly name used in a UI for this login.
		/// </summary>
		public virtual string ProviderDisplayName { get; set; }
        public virtual TKey UserId { get; set; }
    }
}
