using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Owin.Security.Keycloak.Utilities
{
    internal class InterfaceContractResolver : DefaultContractResolver
    {
        private readonly Type _interfaceType;

        public InterfaceContractResolver(Type interfaceType)
        {
            _interfaceType = interfaceType;
        }

        protected override IList<JsonProperty> CreateProperties(Type type, MemberSerialization memberSerialization)
        {
            return base.CreateProperties(_interfaceType, memberSerialization);
        }
    }
}