using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace RevStackCore.Identity
{
    public static partial class ExtensionHelpers
    {

		/// <summary>
		/// Exception handling for SingleOrDefault() 
		/// </summary>
		/// <returns>The single or default.</returns>
		/// <param name="src">Source.</param>
		/// <typeparam name="TSource">The 1st type parameter.</typeparam>
		public static TSource ToSingleOrDefault<TSource>(this IEnumerable<TSource> src)
        {
            try
            {
                return src.SingleOrDefault();
            }
            catch (Exception)
            {
                if (src != null && src.Any())
                {
                    return src.FirstOrDefault();
                }
                else
                {
                    return default(TSource);
                }
            }
        }


		/// <summary>
		/// Uses EqualityComparer<T>.Default as an equality comparison for generics not constrained by a reference type
		/// </summary>
		/// <returns>The compare.</returns>
		/// <param name="src">Source.</param>
		/// <param name="id">Identifier.</param>
		/// <param name="value">Value.</param>
		/// <typeparam name="TSource">The 1st type parameter.</typeparam>
		/// <typeparam name="TKey">The 2nd type parameter.</typeparam>
		public static bool Compare<TSource, TKey>(this TSource src, TKey id, TKey value)
        {
            return EqualityComparer<TKey>.Default.Equals(id, value);
        }
    }
}
