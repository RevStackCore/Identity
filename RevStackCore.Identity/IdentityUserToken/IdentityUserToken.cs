﻿using System;
using System.Collections.Generic;
using System.Text;

namespace RevStackCore.Identity
{
    public class IdentityUserToken : IdentityUserToken<string>
    {
        public IdentityUserToken()
        {
            Id = Guid.NewGuid().ToString();
        }
    }

    /// <summary>
	///     Represents an authentication token for a user.
	/// </summary>
	/// <typeparam name="TKey">The type of the primary key used for users.</typeparam>
	public class IdentityUserToken<TKey> : IIdentityUserToken<TKey>
    {
        public virtual TKey Id { get; set; }

        /// <summary>
        ///     Gets or sets the primary key of the user that the token belongs to.
        /// </summary>
        public virtual TKey UserId { get; set; }

        /// <summary>
        ///     Gets or sets the LoginProvider this token is from.
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        ///     Gets or sets the name of the token.
        /// </summary>
        public virtual string Name { get; set; }

        /// <summary>
        ///     Gets or sets the token value.
        /// </summary>
        public virtual string Value { get; set; }
    }
}
