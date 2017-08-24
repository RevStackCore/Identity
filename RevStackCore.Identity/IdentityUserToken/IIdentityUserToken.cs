using System;
using RevStackCore.Pattern;

namespace RevStackCore.Identity
{
    /// <summary>
	///     Represents an authentication token for a user.
	/// </summary>
	/// <typeparam name="TKey">The type of the primary key used for users.</typeparam>
	public interface IIdentityUserToken<TKey>  : IEntity<TKey>
    {
        /// <summary>
        ///     Gets or sets the primary key of the user that the token belongs to.
        /// </summary>
        TKey UserId { get; set; }

        /// <summary>
        ///     Gets or sets the LoginProvider this token is from.
        /// </summary>
        string LoginProvider { get; set; }

        /// <summary>
        ///     Gets or sets the name of the token.
        /// </summary>
        string Name { get; set; }

        /// <summary>
        ///     Gets or sets the token value.
        /// </summary>
        string Value { get; set; }
    }
}
