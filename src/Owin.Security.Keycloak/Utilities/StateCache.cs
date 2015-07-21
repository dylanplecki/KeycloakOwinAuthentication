using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Web;
using System.Web.Caching;

namespace Owin.Security.Keycloak.Utilities
{
    internal static class StateCache
    {
        private const string CachePrefix = "oidc_state_";
        private static readonly TimeSpan DefaultCacheLife = new TimeSpan(0, 30, 0); // 30 Minutes

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Cache GetCache()
        {
            return HttpRuntime.Cache;
        }

        public static string CreateState(Dictionary<string, object> stateData, TimeSpan? lifeTime = null)
        {
            if (lifeTime == null) lifeTime = DefaultCacheLife;

            // Generate state key
            var stateKey = CachePrefix + Guid.NewGuid().ToString("N");

            // Insert into cache
            GetCache().Insert(stateKey, stateData, null, Cache.NoAbsoluteExpiration, lifeTime.Value);

            return stateKey;
        }

        public static Dictionary<string, object> ReturnState(string stateKey)
        {
            return GetCache().Remove(stateKey) as Dictionary<string, object>;
        }

        public static class PropertyNames
        {
            public const string ReturnUri = "returnUri";
            public const string AuthenticationProperties = "authProperties";
        }
    }
}
