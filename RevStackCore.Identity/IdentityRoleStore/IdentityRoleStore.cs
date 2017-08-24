using System;
using System.Threading.Tasks;
using RevStackCore.Pattern;
using RevStackCore.Extensions.Mvc;
using Microsoft.AspNetCore.Identity;
using System.Threading;
using System.ComponentModel;

namespace RevStackCore.Identity
{
    public class IdentityRoleStore<TRole, TKey> : IIdentityRoleStore<TRole, TKey> where TRole : class, IIdentityRole<TKey>
    {
        #region "Private Fields"
        private readonly IRepository<TRole, TKey> _roleRepository;
        #endregion

        #region "Constructor"
        public IdentityRoleStore(IRepository<TRole, TKey> roleRepository)
        {
            _roleRepository = roleRepository;
           
        }
        #endregion

        #region "Public Members"
        /// <summary>
		///     Creates a new role in a store as an asynchronous operation.
		/// </summary>
		/// <param name="role">The role to create in the store.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that represents the <see cref="IdentityResult" /> of the asynchronous query.</returns>
		public async Task<IdentityResult> CreateAsync(TRole role,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            await Task.Run(() => _create(role), cancellationToken);
            return IdentityResult.Success;
        }

        /// <summary>
        ///     Deletes a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to delete from the store.</param>
        /// <param name="cancellationToken">
        ///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
        ///     should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}" /> that represents the <see cref="IdentityResult" /> of the asynchronous query.</returns>
        public async Task<IdentityResult> DeleteAsync(TRole role,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            var result = await Task.Run(() => _delete(role), cancellationToken);
            return result == 1 ? IdentityResult.Success : IdentityResult.Failed();
        }

        /// <summary>
        ///     Finds the role who has the specified ID as an asynchronous operation.
        /// </summary>
        /// <param name="id">The role ID to look for.</param>
        /// <param name="cancellationToken">
        ///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
        ///     should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}" /> that result of the look up.</returns>
        public async Task<TRole> FindByIdAsync(TKey id, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            //var roleId = ConvertIdFromString(id);

            return await Task.FromResult(_findById(id));
        }

        /// <summary>
        ///     Finds the role who has the specified normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="normalizedName">The normalized role name to look for.</param>
        /// <param name="cancellationToken">
        ///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
        ///     should be canceled.
        /// </param>
        /// <returns>A <see cref="Task{TResult}" /> that result of the look up.</returns>
        public async Task<TRole> FindByNameAsync(string normalizedName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return await Task.FromResult(_findByName(normalizedName));
        }

        /// <summary>
		///     Updates a role in a store as an asynchronous operation.
		/// </summary>
		/// <param name="role">The role to update in the store.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that represents the <see cref="IdentityResult" /> of the asynchronous query.</returns>
		public async Task<IdentityResult> UpdateAsync(TRole role,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));

            var result = await Task.Run(() => _update(role), cancellationToken);
            return result == 1 ? IdentityResult.Success : IdentityResult.Failed();
        }

        /// <summary>
		///     Gets the ID for a role from the store as an asynchronous operation.
		/// </summary>
		/// <param name="role">The role whose ID should be returned.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that contains the ID of the role.</returns>
		public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            return Task.FromResult(ConvertIdToString(role.Id));
        }

        /// <summary>
		///     Gets the name of a role from the store as an asynchronous operation.
		/// </summary>
		/// <param name="role">The role whose name should be returned.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that contains the name of the role.</returns>
		public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            return Task.FromResult(role.Name);
        }

        /// <summary>
		///     Sets the name of a role in the store as an asynchronous operation.
		/// </summary>
		/// <param name="role">The role whose name should be set.</param>
		/// <param name="roleName">The name of the role.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
		public Task SetRoleNameAsync(TRole role, string roleName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            role.Name = roleName;
            return Task.Run(() => _update(role), cancellationToken);
        }

        /// <summary>
		///     Get a role's normalized name as an asynchronous operation.
		/// </summary>
		/// <param name="role">The role whose normalized name should be retrieved.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that contains the name of the role.</returns>
		public virtual Task<string> GetNormalizedRoleNameAsync(TRole role,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            return Task.FromResult(role.NormalizedName);
        }

        /// <summary>
        ///     Set a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be set.</param>
        /// <param name="normalizedName">The normalized name to set</param>
        /// <param name="cancellationToken">
        ///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
        ///     should be canceled.
        /// </param>
        /// <returns>The <see cref="Task" /> that represents the asynchronous operation.</returns>
        public virtual Task SetNormalizedRoleNameAsync(TRole role, string normalizedName,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null)
                throw new ArgumentNullException(nameof(role));
            role.NormalizedName = normalizedName;
            return Task.Run(() => _update(role), cancellationToken);
        }

        /// <summary>
		///     Finds the role who has the specified ID as an asynchronous operation.
		/// </summary>
		/// <param name="id">The role ID to look for.</param>
		/// <param name="cancellationToken">
		///     The <see cref="CancellationToken" /> used to propagate notifications that the operation
		///     should be canceled.
		/// </param>
		/// <returns>A <see cref="Task{TResult}" /> that result of the look up.</returns>
		public async Task<TRole> FindByIdAsync(string id, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            var roleId = ConvertIdFromString(id);

            return await Task.FromResult(_findById(roleId));
        }
        #endregion


        #region "Private Members"
        private void _create(TRole role)
        {
            _roleRepository.Add(role);
        }

        private int _delete(TRole role)
        {
            _roleRepository.Delete(role);
            return 1;
        }

        private TRole _find(TRole role)
        {
            return (TRole)_roleRepository.Find(x => x.Compare(x.Id, role.Id)).ToSingleOrDefault();
        }

        private TRole _findById(TKey roleId)
        {
            return (TRole)_roleRepository.Find(x => x.Compare(x.Id, roleId)).ToSingleOrDefault();
        }
        private TRole _findByName(string roleName)
        {
            return (TRole)_roleRepository.Find(x => x.Name==roleName).ToSingleOrDefault();
        }

        private int _update(TRole role)
        {
            _roleRepository.Update(role);
            return 1;
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
