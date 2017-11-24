using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using RevStackCore.Pattern;
using System.Threading;
using System.ComponentModel;

namespace RevStackCore.Identity
{
    public class IdentityUserStore<TUser,TUserLogin,TUserClaim,TUserRole,TRole,TKey,TUserToken> : IIdentityUserStore<TUser,TKey> 
        where TUser : class,IIdentityUser<TKey>
        where TUserLogin : class,IIdentityUserLogin<TKey>, new()
        where TUserClaim : class,IIdentityUserClaim<TKey>, new()
        where TUserRole : class, IIdentityUserRole<TKey>, new()
        where TUserToken : class, IIdentityUserToken<TKey>, new()
        where TRole : class, IIdentityRole<TKey>
    {
        #region "Private Fields"
        private const string DUPLICATE_USER_MSG = "Error: Cannot Create User.Username already in use";
        private readonly IRepository<TUser, TKey> _userRepository;
        private readonly IRepository<TUserLogin, TKey> _userLoginRepository;
        private readonly IRepository<TUserClaim, TKey> _userClaimRepository;
        private readonly IRepository<TUserRole, TKey> _userRoleRepository;
        private readonly IRepository<TRole, TKey> _roleRepository;
        private readonly IRepository<TUserToken, TKey> _userTokenRepository;

        #endregion

        #region "Constructor"
        public IdentityUserStore(IRepository<TUser, TKey> userRepository, 
            IRepository<TUserLogin, TKey> userLoginRepository,
            IRepository<TUserClaim, TKey> userClaimRepository, 
            IRepository<TUserRole, TKey> userRoleRepository,
            IRepository<TRole, TKey> roleRepository,
            IRepository<TUserToken, TKey> userTokenRepository

            )
        {
            _userRepository = userRepository;
            _userLoginRepository = userLoginRepository;
            _userClaimRepository = userClaimRepository;
            _userRoleRepository = userRoleRepository;
            _roleRepository = roleRepository;
            _userTokenRepository = userTokenRepository;
        }
        #endregion

        #region "Public Members"

        /// <summary>
		///     Sets the token value for a particular user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="loginProvider">The authentication provider for the token.</param>
		/// <param name="name">The name of the token.</param>
		/// <param name="value">The value of the token.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task SetTokenAsync(TUser user, string loginProvider, string name, string value, 
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            await Task.Run(() =>
            {

                _setUserToken(CreateUserToken(user, loginProvider, name, value));

            }, cancellationToken);
        }

        /// <summary>
		///     Deletes a token for a user.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="loginProvider">The authentication provider for the token.</param>
		/// <param name="name">The name of the token.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task RemoveTokenAsync(TUser user, string loginProvider, string name,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            await Task.Run(() =>
            {

                _removeUserToken(user, loginProvider, name);

            }, cancellationToken);
        }

        /// <summary>
		///     Returns the token value.
		/// </summary>
		/// <param name="user">The user.</param>
		/// <param name="loginProvider">The authentication provider for the token.</param>
		/// <param name="name">The name of the token.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task<string> GetTokenAsync(TUser user, string loginProvider, string name,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return await Task.Run(() =>
            {

                return _getUserToken(user, loginProvider, name).Value;

            }, cancellationToken);
        }

        /// <summary>
		///     Creates the specified <paramref name="user" /> in the user store.
		/// </summary>
		/// <param name="user">The user to create.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the
		///     <see cref="IdentityResult" /> of the creation operation.
		/// </returns>
        public async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            await Task.Run(() => _create(user), cancellationToken);
            
            return IdentityResult.Success;
        }

        /// <summary>
		///     Deletes the specified <paramref name="user" /> from the user store.
		/// </summary>
		/// <param name="user">The user to delete.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the
		///     <see cref="IdentityResult" /> of the update operation.
		/// </returns>
		public async Task<IdentityResult> DeleteAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var result = await Task.Run(() => _delete(user), cancellationToken);

            return result == 1 ? IdentityResult.Success : IdentityResult.Failed();
        }

        /// <summary>
		///     Finds and returns a user, if any, who has the specified <paramref name="userId" />.
		/// </summary>
		/// <param name="userId">The user ID to search for.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the user matching the specified
		///     <paramref name="userId" /> if it exists.
		/// </returns>
		public async Task<TUser> FindByIdAsync(string userId,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var id = ConvertIdFromString(userId);

            return await Task.Run(() => _findById(id), cancellationToken);
        }

        /// <summary>
		///     Finds and returns a user, if any, who has the specified normalized user name.
		/// </summary>
		/// <param name="userName">The normalized user name to search for.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the user matching the specified
		///     <paramref name="userName" /> if it exists.
		/// </returns>
		public async Task<TUser> FindByNameAsync(string userName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return await Task.Run(() => _findByName(userName), cancellationToken);
        }

        /// <summary>
		///     Updates the specified <paramref name="user" /> in the user store.
		/// </summary>
		/// <param name="user">The user to update.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the
		///     <see cref="IdentityResult" /> of the update operation.
		/// </returns>
		public async Task<IdentityResult> UpdateAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            var result = await Task.Run(() => _update(user), cancellationToken);

            return result == 1 ? IdentityResult.Success : IdentityResult.Failed();
        }

        /// <summary>
		///     Adds the <paramref name="login" /> given to the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to add the login to.</param>
		/// <param name="login">The login to add to the user.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task AddLoginAsync(TUser user, UserLoginInfo login,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (login == null)
                throw new ArgumentNullException(nameof(login));

            await Task.Run(() => _addLogin(user, login), cancellationToken);
        }

        /// <summary>
		///     Removes the <paramref name="loginProvider" /> given from the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to remove the login from.</param>
		/// <param name="loginProvider">The login to remove from the user.</param>
		/// <param name="providerKey">The key provided by the <paramref name="loginProvider" /> to identify a user.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            
            await Task.Run(() => _removeLogin(user, loginProvider, providerKey), cancellationToken);
        }

        /// <summary>
		///     Retrieves the associated logins for the specified
		///     <param ref="user" />
		///     .
		/// </summary>
		/// <param name="user">The user whose associated logins to retrieve.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> for the asynchronous operation, containing a list of <see cref="UserLoginInfo" /> for the
		///     specified <paramref name="user" />, if any.
		/// </returns>
		public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return await Task.Run(() => _getLogins(user), cancellationToken);
        }

        public virtual Task<TUser> FindAsync(UserLoginInfo login)
        {
            return Task.FromResult(_find(login));
        }

        /// <summary>
		///     Get the claims associated with the specified <paramref name="user" /> as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user whose claims should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that contains the claims granted to a user.</returns>
		public async Task<IList<Claim>> GetClaimsAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            
            return await Task.Run(() => _getClaims(user), cancellationToken);
        }

        /// <summary>
		///     Adds the <paramref name="claims" /> given to the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to add the claim to.</param>
		/// <param name="claims">The claim to add to the user.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));
            
            Task.Run(() => _addClaims(user, claims), cancellationToken);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Removes the <paramref name="claims" /> given from the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to remove the claims from.</param>
		/// <param name="claims">The claim to remove.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claims == null)
                throw new ArgumentNullException(nameof(claims));
            
            await Task.Run(() => _removeClaims(user, claims), cancellationToken);
            //return Task.FromResult(true);
        }

        /// <summary>
		///     Adds the given <paramref name="normalizedRoleName" /> to the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to add the role to.</param>
		/// <param name="normalizedRoleName">The role to add.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task AddToRoleAsync(TUser user, string normalizedRoleName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException("Value Cannot Be Null Or Empty", nameof(normalizedRoleName));

            await Task.Run(() => _addToRole(user, normalizedRoleName), cancellationToken);
        }

        /// <summary>
		///     Removes the given <paramref name="normalizedRoleName" /> from the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user to remove the role from.</param>
		/// <param name="normalizedRoleName">The role to remove.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task RemoveFromRoleAsync(TUser user, string normalizedRoleName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException("Value Cannot Be Null Or Empty", nameof(normalizedRoleName));

            await Task.Run(() => _removeFromRole(user, normalizedRoleName), cancellationToken);
        }

        /// <summary>
		///     Retrieves the roles the specified <paramref name="user" /> is a member of.
		/// </summary>
		/// <param name="user">The user whose roles should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that contains the roles the user is a member of.</returns>
		public async Task<IList<string>> GetRolesAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            
            return await Task.Run(() => _getRoles(user), cancellationToken);
        }

        /// <summary>
		///     Returns a flag indicating if the specified user is a member of the give <paramref name="normalizedRoleName" />.
		/// </summary>
		/// <param name="user">The user whose role membership should be checked.</param>
		/// <param name="normalizedRoleName">The role to check membership of</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     A <see cref="Task{TResult}" /> containing a flag indicating if the specified user is a member of the given group.
		///     If the
		///     user is a member of the group the returned value with be true, otherwise it will be false.
		/// </returns>
		public async Task<bool> IsInRoleAsync(TUser user, string normalizedRoleName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (string.IsNullOrWhiteSpace(normalizedRoleName))
                throw new ArgumentException("Value Cannot Be Null Or Empty", nameof(normalizedRoleName));

            return await Task.Run(() => _isInRole(user, normalizedRoleName), cancellationToken);
        }

        /// <summary>
		///     Sets the password hash for a user.
		/// </summary>
		/// <param name="user">The user to set the password hash for.</param>
		/// <param name="passwordHash">The password hash to set.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public virtual Task SetPasswordHashAsync(TUser user, string passwordHash,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setPasswordHash(user, passwordHash);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Gets the password hash for a user.
		/// </summary>
		/// <param name="user">The user to retrieve the password hash for.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that contains the password hash for the user.</returns>
		public virtual Task<string> GetPasswordHashAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getPasswordHash(user));
        }

        /// <summary>
		///     Returns a flag indicating if the specified user has a password.
		/// </summary>
		/// <param name="user">The user to retrieve the password hash for.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     A <see cref="Task{TResult}" /> containing a flag indicating if the specified user has a password. If the
		///     user has a password the returned value with be true, otherwise it will be false.
		/// </returns>
		public virtual Task<bool> HasPasswordAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(_hasPassword(user));
        }

        /// <summary>
		///     Sets the provided security <paramref name="stamp" /> for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose security stamp should be set.</param>
		/// <param name="stamp">The security stamp to set.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public virtual Task SetSecurityStampAsync(TUser user, string stamp,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setSecurityStamp(user, stamp);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Get the security stamp for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose security stamp should be set.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the security stamp for the
		///     specified <paramref name="user" />.
		/// </returns>
		public virtual Task<string> GetSecurityStampAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getSecurityStamp(user));
        }

        /// <summary>
		///     Sets the <paramref name="email" /> address for a <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose email should be set.</param>
		/// <param name="email">The email to set.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		public virtual Task SetEmailAsync(TUser user, string email,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setEmail(user, email);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Gets the email address for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose email should be returned.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The task object containing the results of the asynchronous operation, the email address for the specified
		///     <paramref name="user" />.
		/// </returns>
		public virtual Task<string> GetEmailAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getEmail(user));
        }

        /// <summary>
		///     Gets a flag indicating whether the email address for the specified <paramref name="user" /> has been verified, true
		///     if the email address is verified otherwise
		///     false.
		/// </summary>
		/// <param name="user">The user whose email confirmation status should be returned.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The task object containing the results of the asynchronous operation, a flag indicating whether the email address
		///     for the specified <paramref name="user" />
		///     has been confirmed or not.
		/// </returns>
		public virtual Task<bool> GetEmailConfirmedAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getEmailConfirmed(user));
        }

        /// <summary>
		///     Sets the flag indicating whether the specified <paramref name="user" />'s email address has been confirmed or not.
		/// </summary>
		/// <param name="user">The user whose email confirmation status should be set.</param>
		/// <param name="confirmed">
		///     A flag indicating if the email address has been confirmed, true if the address is confirmed
		///     otherwise false.
		/// </param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The task object representing the asynchronous operation.</returns>
		public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setEmailConfirmed(user, confirmed);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Gets the user, if any, associated with the specified, normalized email address.
		/// </summary>
		/// <param name="normalizedEmail">The normalized email address to return the user for.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The task object containing the results of the asynchronous lookup operation, the user if any associated with the
		///     specified normalized email address.
		/// </returns>
		public async Task<TUser> FindByEmailAsync(string normalizedEmail,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            
            return await Task.Run(() => _findByEmail(normalizedEmail), cancellationToken);
        }

        /// <summary>
		///     Sets the telephone number for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose telephone number should be set.</param>
		/// <param name="phoneNumber">The telephone number to set.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setPhoneNumber(user, phoneNumber);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Gets the telephone number, if any, for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose telephone number should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the user's telephone number, if
		///     any.
		/// </returns>
		public virtual Task<string> GetPhoneNumberAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getPhoneNumber(user));
        }

        /// <summary>
		///     Gets a flag indicating whether the specified <paramref name="user" />'s telephone number has been confirmed.
		/// </summary>
		/// <param name="user">The user to return a flag for, indicating whether their telephone number is confirmed.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, returning true if the specified
		///     <paramref name="user" /> has a confirmed
		///     telephone number otherwise false.
		/// </returns>
		public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getPhoneNumberConfirmed(user));
        }

        /// <summary>
		///     Sets a flag indicating if the specified <paramref name="user" />'s phone number has been confirmed..
		/// </summary>
		/// <param name="user">The user whose telephone number confirmation status should be set.</param>
		/// <param name="confirmed">A flag indicating whether the user's telephone number has been confirmed.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setPhoneNumberConfirmed(user, confirmed);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Gets the last <see cref="DateTimeOffset" /> a user's last lockout expired, if any.
		///     Any time in the past should be indicates a user is not locked out.
		/// </summary>
		/// <param name="user">The user whose lockout date should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     A <see cref="Task{TResult}" /> that represents the result of the asynchronous query, a
		///     <see cref="DateTimeOffset" /> containing the last time
		///     a user's lockout expired, if any.
		/// </returns>
		public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getLockoutEndDate(user));
        }

        /// <summary>
		///     Locks out a user until the specified end date has passed. Setting a end date in the past immediately unlocks a
		///     user.
		/// </summary>
		/// <param name="user">The user whose lockout date should be set.</param>
		/// <param name="lockoutEnd">
		///     The <see cref="DateTimeOffset" /> after which the <paramref name="user" />'s lockout should
		///     end.
		/// </param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setLockoutEndDate(user, lockoutEnd);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Records that a failed access has occurred, incrementing the failed access count.
		/// </summary>
		/// <param name="user">The user whose cancellation count should be incremented.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the incremented failed access
		///     count.
		/// </returns>
		public virtual Task<int> IncrementAccessFailedCountAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_incrementAccessFailedCount(user));
        }

        /// <summary>
		///     Resets a user's failed access count.
		/// </summary>
		/// <param name="user">The user whose failed access count should be reset.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		/// <remarks>This is typically called after the account is successfully accessed.</remarks>
		public virtual Task ResetAccessFailedCountAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _resetAccessFailedCount(user);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Retrieves the current failed access count for the specified <paramref name="user" />..
		/// </summary>
		/// <param name="user">The user whose failed access count should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation, containing the failed access count.</returns>
		public virtual Task<int> GetAccessFailedCountAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.Run(()=> _getAccessFailedCount(user), cancellationToken);
        }

        /// <summary>
		///     Retrieves a flag indicating whether user lockout can enabled for the specified user.
		/// </summary>
		/// <param name="user">The user whose ability to be locked out should be returned.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, true if a user can be locked out, otherwise
		///     false.
		/// </returns>
		public virtual Task<bool> GetLockoutEnabledAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getLockoutEnabled(user));
        }

        /// <summary>
		///     Set the flag indicating if the specified <paramref name="user" /> can be locked out..
		/// </summary>
		/// <param name="user">The user whose ability to be locked out should be set.</param>
		/// <param name="enabled">A flag indicating if lock out can be enabled for the specified <paramref name="user" />.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setLockoutEnabled(user, enabled);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Sets a flag indicating whether the specified <paramref name="user" /> has two factor authentication enabled or not,
		///     as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user whose two factor authentication enabled status should be set.</param>
		/// <param name="enabled">
		///     A flag indicating whether the specified <paramref name="user" /> has two factor authentication
		///     enabled.
		/// </param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setTwoFactorEnabled(user, enabled);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Returns a flag indicating whether the specified <paramref name="user" /> has two factor authentication enabled or
		///     not,
		///     as an asynchronous operation.
		/// </summary>
		/// <param name="user">The user whose two factor authentication enabled status should be set.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing a flag indicating whether the
		///     specified
		///     <paramref name="user" /> has two factor authentication enabled or not.
		/// </returns>
		public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getTwoFactorEnabled(user));
        }

        /// <summary>
		///     Returns the normalized email for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose email address to retrieve.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The task object containing the results of the asynchronous lookup operation, the normalized email address if any
		///     associated with the specified user.
		/// </returns>
		public virtual Task<string> GetNormalizedEmailAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getNormalizedEmail(user));
        }

        /// <summary>
        ///     Sets the normalized email for the specified <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user whose email address to set.</param>
        /// <param name="normalizedEmail">The normalized email to set for the specified <paramref name="user" />.</param>
        /// <param name="cancellationToken">
        ///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
        ///     should be canceled.
        /// </param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        public virtual Task SetNormalizedEmailAsync(TUser user, string normalizedEmail,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setNormalizedEmail(user, normalizedEmail);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Gets the normalized user name for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose normalized name should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the normalized user name for
		///     the specified <paramref name="user" />.
		/// </returns>
		public virtual Task<string> GetNormalizedUserNameAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(_getNormalizedUserName(user));
        }

        /// <summary>
		///     Gets the user identifier for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose identifier should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the identifier for the
		///     specified <paramref name="user" />.
		/// </returns>
		public virtual Task<string> GetUserIdAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            return Task.FromResult(ConvertIdToString(user.Id));
        }

        /// <summary>
        ///     Sets the given normalized name for the specified <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="normalizedName">The normalized name to set.</param>
        /// <param name="cancellationToken">
        ///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
        ///     should be canceled.
        /// </param>
        /// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
        public virtual Task SetNormalizedUserNameAsync(TUser user, string normalizedName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setNormalizedUserName(user, normalizedName);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Gets the user name for the specified <paramref name="user" />.
		/// </summary>
		/// <param name="user">The user whose name should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> that represents the asynchronous operation, containing the name for the specified
		///     <paramref name="user" />.
		/// </returns>
		public virtual Task<string> GetUserNameAsync(TUser user,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            return Task.FromResult(_getUserName(user));
        }

        /// <summary>
        ///     Sets the given <paramref name="userName" /> for the specified <paramref name="user" />.
        /// </summary>
        /// <param name="user">The user whose name should be set.</param>
        /// <param name="userName">The user name to set.</param>
        /// <param name="cancellationToken">
        ///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
        ///     should be canceled.
        /// </param>
        /// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
        public virtual Task SetUserNameAsync(TUser user, string userName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));

            _setUserName(user, userName);
            return Task.FromResult(true);
        }

        /// <summary>
		///     Retrieves the user associated with the specified login provider and login provider key..
		/// </summary>
		/// <param name="loginProvider">The login provider who provided the <paramref name="providerKey" />.</param>
		/// <param name="providerKey">The key provided by the <paramref name="loginProvider" /> to identify a user.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> for the asynchronous operation, containing the user, if any which matched the specified
		///     login provider and key.
		/// </returns>
		public async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(loginProvider))
                throw new ArgumentException("Value Cannot Be Null Or Empty", nameof(loginProvider));
            if (string.IsNullOrWhiteSpace(providerKey))
                throw new ArgumentException("Value Cannot Be Null Or Empty", nameof(providerKey));

            return await Task.Run(() => _findByLogin(loginProvider, providerKey), cancellationToken);
        }

        /// <summary>
		///     Retrieves all users in the specified role.
		/// </summary>
		/// <param name="normalizedRoleName">The role whose users should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> contains a list of users, if any, that are in the specified role.
		/// </returns>
		public async Task<IList<TUser>> GetUsersInRoleAsync(string normalizedRoleName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrEmpty(normalizedRoleName))
                throw new ArgumentNullException(nameof(normalizedRoleName));

            return await Task.Run(() => _getUsersInRole(normalizedRoleName), cancellationToken);
        }

        /// <summary>
		///     Retrieves all users with the specified claim.
		/// </summary>
		/// <param name="claim">The claim whose users should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>
		///     The <see cref="Task" /> contains a list of users, if any, that contain the specified claim.
		/// </returns>
		public async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));

            return await Task.Run(() => _getUsersForClaim(claim), cancellationToken);
        }

        /// <summary>
		///     Replaces the <paramref name="claim" /> on the specified <paramref name="user" />, with the
		///     <paramref name="newClaim" />.
		/// </summary>
		/// <param name="user">The role to replace the claim on.</param>
		/// <param name="claim">The claim replace.</param>
		/// <param name="newClaim">The new claim replacing the <paramref name="claim" />.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            ThrowIfDisposed();
            if (user == null)
                throw new ArgumentNullException(nameof(user));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));
            if (newClaim == null)
                throw new ArgumentNullException(nameof(newClaim));

            await Task.Run(() => _replaceUserClaim(user, claim, newClaim), cancellationToken);
        }
        /// <summary>
        /// Gets the users.
        /// </summary>
        /// <value>The users.</value>
        public IQueryable<TUser> Users
        {
            get
            {
                var users = _userRepository.Get();
                return users.AsQueryable();
            }
        }
        #endregion

        #region "Private Members"
        private void _setUserToken(TUserToken userToken)
        {
            _userTokenRepository.Add(userToken);
        }

        private void _removeUserToken(TUser user, string loginProvider, string name)
        {
            var userToken = _getUserToken(user, loginProvider, name);
            if (userToken != null)
            {
                _userTokenRepository.Delete(userToken);
            }
        }

        private TUserToken _getUserToken(TUser user, string loginProvider, string name)
        {
            return _userTokenRepository.Find(x => x.UserId.Equals(user.Id) && x.LoginProvider == loginProvider && x.Name == name).FirstOrDefault();
        }

        private void _create(TUser user)
        {
            _userRepository.Add(user);
        }

        private int _delete(TUser user)
        {
            _userRepository.Delete(user);
            return 1;
        }

        private TUser _findById(TKey userId)
        {
            return (TUser)_userRepository.Find(x => x.Compare(x.Id, userId)).ToSingleOrDefault();
        }

        private TUser _findByName(string userName)
        {
            return (TUser)_userRepository.Find(x => x.UserName.ToLower() == userName.ToLower()).ToSingleOrDefault();
        }

        private int _update(TUser user)
        {
            try
            {
                var userUpdated = _userRepository.Update(user);
                if (userUpdated != null)
                {
                    return 1;
                }
            }
            catch (Exception)
            {
                return 0;
            }
            
            return 0;
        }

        private void _addLogin(TUser user, UserLoginInfo login)
        {
            var identityUserLogin = CreateUserLogin(user, login);
            identityUserLogin.Id = user.Id;
            identityUserLogin.LoginProvider = login.LoginProvider;
            identityUserLogin.ProviderKey = login.ProviderKey;

            _userLoginRepository.Add(identityUserLogin);
        }

        private void _removeLogin(TUser user, string loginProvider, string providerKey)
        {
            var identityLogin = _userLoginRepository.Find(x => x.Compare(x.UserId, user.Id) && x.LoginProvider == loginProvider && x.ProviderKey == providerKey).ToSingleOrDefault();
            if(identityLogin != null)
            {
                _userLoginRepository.Delete(identityLogin);
            }
        }

        private IList<UserLoginInfo> _getLogins(TUser user)
        {
            var logins = _userLoginRepository.Find(x => x.Compare(x.UserId, user.Id));
            if(logins.Any())
            {
                return logins.Select(x => new UserLoginInfo(x.LoginProvider, x.ProviderKey, x.ProviderDisplayName)).ToList();
            }
            else
            {
                return new List<UserLoginInfo>();
            }
        }

        private TUser _find(UserLoginInfo login)
        {
            TUser user = null;
            var userLogin = _userLoginRepository.Find(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey).ToSingleOrDefault();
            if(userLogin !=null)
            {
                user = (TUser)_userRepository.Find(x => x.Compare(x.Id, userLogin.UserId)).ToSingleOrDefault();
            }
            return user;
        }

        private TUser _findByLogin(string loginProvider, string providerKey)
        {
            TUser user = null;
            var userLogin = _userLoginRepository.Find(x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey).ToSingleOrDefault();
            if (userLogin != null)
            {
                user = (TUser)_userRepository.Find(x => x.Compare(x.Id, userLogin.UserId)).ToSingleOrDefault();
            }
            return user;
        }

        private void _replaceUserClaim(TUser user, Claim claim, Claim newClaim)
        {
            var userClaims = _userClaimRepository.Find(x => x.Compare(x.UserId, user.Id) && x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            if (userClaims.Any())
            {
                var userClaim = userClaims.FirstOrDefault();
                userClaim.ClaimType = newClaim.Type;
                userClaim.ClaimValue = newClaim.Value;

                _userClaimRepository.Update(userClaim);
            }
        }

        private IList<Claim> _getClaims(TUser user)
        {
            var userClaims = _userClaimRepository.Find(x => x.Compare(x.UserId, user.Id));
            if(userClaims.Any())
            {
                return userClaims.Select(x => new Claim(x.ClaimType, x.ClaimType)).ToList();
            }
            else
            {
                return new List<Claim>();
            }
        }

        private void _addClaims(TUser user, IEnumerable<Claim> claims)
        {
            foreach (var claim in claims)
            {
                var identityUserClaim = CreateUserClaim(user, claim);
                identityUserClaim.UserId = user.Id;
                identityUserClaim.ClaimType = claim.Type;
                identityUserClaim.ClaimValue = claim.Value;

                _userClaimRepository.Add(identityUserClaim);
            }
        }

        private void _removeClaims(TUser user, IEnumerable<Claim> claims)
        {
            foreach (var claim in claims)
            {
                _removeClaim(user, claim);
            }
        }

        private void _removeClaim(TUser user, Claim claim)
        {
            var userClaims = _userClaimRepository.Find(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value && x.Compare(x.UserId, user.Id));
            if(userClaims.Any())
            {
                var userClaim = userClaims.ToSingleOrDefault();
                _userClaimRepository.Delete(userClaim);
            }
        }

        private IList<TUser> _getUsersForClaim(Claim claim)
        {
            var userClaims = _userClaimRepository.Find(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
            if (userClaims.Any())
            {
                return _listOfUsers(userClaims);
            }
            return default(List<TUser>);
        }

        private List<TUser> _listOfUsers(IQueryable<TUserClaim> userClaims)
        {
            return userClaims
              .Join(_userRepository.Get(), x => x.UserId, r => r.Id, (x, r) => new { x, r })
              .Select(result => result.r).ToList();
        }

        private void _addToRole(TUser user, string roleName)
        {
            var role = _roleRepository.Find(x => x.Name.ToLower() == roleName.ToLower()).ToSingleOrDefault();
            if(role!=null)
            {
                var identityUserRole = CreateUserRole(user, role.Id);
                identityUserRole.UserId = user.Id;
                identityUserRole.RoleId = role.Id.ToString();

                _userRoleRepository.Add(identityUserRole);
            }
        }

        private void _removeFromRole(TUser user, string roleName)
        {
            var role = _roleRepository.Find(x => x.Name.ToLower() == roleName.ToLower()).ToSingleOrDefault();
            if (role != null)
            {
                var userRole = _userRoleRepository.Find(x => x.Compare(x.UserId, user.Id) && x.RoleId.ToLower() == role.Id.ToString().ToLower()).ToSingleOrDefault();
                if(userRole !=null)
                {
                    _userRoleRepository.Delete(userRole);
                }
            }
        }

        private IList<TUser> _getUsersInRole(string roleName)
        {
            var role = _roleRepository.Find(x => x.Name.ToLower() == roleName.ToLower()).ToSingleOrDefault();
            if (role != null)
            {
                var userRoles = _userRoleRepository.Find(x => x.RoleId.ToLower() == role.Id.ToString().ToLower());
                if (userRoles.Any())
                {
                    return _listOfUsers(userRoles);
                }
            }
            return default(List<TUser>);
        }

        private List<TUser> _listOfUsers(IQueryable<IIdentityUserRole<TKey>> roles)
        {
            return roles
              .Join(_userRepository.Get(), x => x.UserId, r => r.Id, (x, r) => new { x, r })
              .Select(result => result.r).ToList();
        }

        private IList<string> _getRoles(TUser user)
        {
            var roles = _userRoleRepository.Find(x => x.Compare(x.UserId, user.Id));
            if(roles.Any())
            {
                return _listOfRoles(roles);
            }
            else
            {
                return new List<string>();
            }
        }

        private List<string> _listOfRoles(IQueryable<IIdentityUserRole<TKey>> roles)
        {
            return roles
              .Join(_roleRepository.Get(), x => x.RoleId, r => r.Id.ToString(), (x, r) => new { x, r })
              .Select(result => result.r.Name).ToList();
        }

        private bool _isInRole(TUser user, string roleName)
        {
            var roles = _userRoleRepository.Find(x => x.Compare(x.UserId, user.Id));
            if (roles.Any())
            {
                return _listOfRoles(roles).Select(x => x.ToLower() == roleName.ToLower()).SingleOrDefault();
            }
            else
            {
                return false;
            }
        }

        private void _setPasswordHash(TUser user, string passwordHash)
        {
            user.PasswordHash = passwordHash;
            if (_userExists(user.UserName)) _userRepository.Update(user);
        }

        private string _getPasswordHash(TUser user)
        {
            return user.PasswordHash;
        }

        private bool _hasPassword(TUser user)
        {
            return (user.PasswordHash != null);
        }

        private void _setSecurityStamp(TUser user, string stamp)
        {
            user.SecurityStamp = stamp;
            if (_userExists(user.UserName)) _userRepository.Update(user);
        }

        private string _getSecurityStamp(TUser user)
        {
            return user.SecurityStamp;
        }

        private void _setEmail(TUser user, string email)
        {
            user.Email = email;
            if(_userExists(user.UserName)) _userRepository.Update(user);
        }

        private string _getEmail(TUser user)
        {
            return user.Email;
        }

        private void _setNormalizedEmail(TUser user, string normalizedEmail)
        {
            user.NormalizedEmail = normalizedEmail;
            if (_userExists(user.UserName)) _userRepository.Update(user);
        }

        private string _getNormalizedEmail(TUser user)
        {
            return user.NormalizedEmail;
        }

        private void _setNormalizedUserName(TUser user, string normalizedUserName)
        {
            user.NormalizedUserName = normalizedUserName;
            if (_userExists(user.UserName)) _userRepository.Update(user);
        }

        private string _getNormalizedUserName(TUser user)
        {
            return user.NormalizedUserName;
        }

        private bool _getEmailConfirmed(TUser user)
        {
            return user.EmailConfirmed;
        }

        private void _setEmailConfirmed(TUser user, bool confirmed)
        {
            user.EmailConfirmed = confirmed;
            _userRepository.Update(user);
        }

        private TUser _findByEmail(string email)
        {
            return (TUser)_userRepository.Find(x => x.Email.ToLower() == email.ToLower()).ToSingleOrDefault();
;        }

        private void _setPhoneNumber(TUser user, string phoneNumber)
        {
            user.PhoneNumber = phoneNumber;
            _userRepository.Update(user);
        }

        private string _getPhoneNumber(TUser user)
        {
            return user.PhoneNumber;
        }

        private bool _getPhoneNumberConfirmed(TUser user)
        {
            return user.PhoneNumberConfirmed;
        }

        private void _setPhoneNumberConfirmed(TUser user, bool confirmed)
        {
            user.PhoneNumberConfirmed = confirmed;
            _userRepository.Update(user);
        }

        private DateTimeOffset? _getLockoutEndDate(TUser user)
        {
            if (user.LockoutEndDate == null) return new DateTimeOffset(DateTime.Now.AddDays(-1));
            return user.LockoutEndDate.Value;
        }

        private void _setLockoutEndDate(TUser user, DateTimeOffset? lockoutEnd)
        {
            user.LockoutEndDate = lockoutEnd;
            _userRepository.Update(user);
        }

        private int _incrementAccessFailedCount(TUser user)
        {
            int count= user.AccessFailedCount++;
            _userRepository.Update(user);
            return count;
        }

        private void _resetAccessFailedCount(TUser user)
        {
            user.AccessFailedCount = 0;
            _userRepository.Update(user);
        }

        private int _getAccessFailedCount(TUser user)
        {
            return user.AccessFailedCount;
        }

        private string _getUserName(TUser user)
        {
            return user.UserName;
        }

        private void _setUserName(TUser user, string userName)
        {
            user.UserName = userName;
            _userRepository.Update(user);
        }

        private bool _getLockoutEnabled(TUser user)
        {
            return user.IsLockoutEnabled;
        }

        private void _setLockoutEnabled(TUser user, bool enabled)
        {
            user.IsLockoutEnabled = enabled;
            _userRepository.Update(user);
        }

        private void _setTwoFactorEnabled(TUser user, bool enabled)
        {
            user.IsTwoFactorEnabled = enabled;
            _userRepository.Update(user);
        }

        private bool _getTwoFactorEnabled(TUser user)
        {
            return user.IsTwoFactorEnabled;
        }

        private bool _userExists(string userName)
        {
            var _existingUser = _findByName(userName);
            return (_existingUser != null);
           
        }

        protected virtual TUserToken CreateUserToken(TUser user, string loginProvider, string name, string value)
        {
            return new TUserToken()
            {
                UserId = user.Id,
                LoginProvider = loginProvider,
                Name = name,
                Value = value
            };
        }

        /// <summary>
		///     Called to create a new instance of a <see cref="IdentityUserLogin{TKey}" />.
		/// </summary>
		/// <param name="user">The associated user.</param>
		/// <param name="login">The sasociated login.</param>
		/// <returns></returns>
		protected virtual TUserLogin CreateUserLogin(TUser user, UserLoginInfo login)
        {
            return new TUserLogin()
            {
                UserId = user.Id,
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName
            };
        }

        /// <summary>
		///     Called to create a new instance of a <see cref="IdentityUserClaim{TKey}" />.
		/// </summary>
		/// <param name="user">The associated user.</param>
		/// <param name="claim">The associated claim.</param>
		/// <returns></returns>
		protected virtual TUserClaim CreateUserClaim(TUser user, Claim claim)
        {
            return new TUserClaim()
            {
                UserId = user.Id,
                ClaimType = claim.Type,
                ClaimValue = claim.Value
            };
        }

        /// <summary>
		///     Called to create a new instance of a <see cref="IdentityUserRole{TKey}" />.
		/// </summary>
		/// <param name="user">The associated user.</param>
		/// <param name="role">The associated role.</param>
		/// <returns></returns>
		protected virtual TUserRole CreateUserRole(TUser user, TKey roleId)
        {
            var id = ConvertIdToString(roleId);
            return new TUserRole()
            {
                UserId = user.Id,
                RoleId = id
            };
        }

        /// <summary>
        ///     Converts the provided <paramref name="id" /> to a strongly typed key object.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey" /> representing the provided <paramref name="id" />.</returns>
        public virtual TKey ConvertIdFromString(string id)
        {
            if (id == null)
                return default(TKey);
            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        /// <summary>
        ///     Converts the provided <paramref name="id" /> to its string representation.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="string" /> representation of the provided <paramref name="id" />.</returns>
        public virtual string ConvertIdToString(TKey id)
        {
            if (Equals(id, default(TKey)))
                return null;
            return id.ToString();
        }
        #endregion


        #region IDisposable Support
        /// <summary>
		///     Throws if this class has been disposed.
		/// </summary>
		protected void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().Name);
        }
        private void disposeWork()
        {
           
        }
        private bool _disposed = false;


        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    disposeWork();
                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
