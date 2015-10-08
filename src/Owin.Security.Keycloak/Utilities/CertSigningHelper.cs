namespace Owin.Security.Keycloak.Utilities
{
    public enum SigningAlgorithm
    {
        Rs256,
        Hs256,
        None
    }

    internal static class CertSigningHelper
    {
        public static SigningAlgorithm LookupSigningAlgorithm(string alg)
        {
            switch (alg)
            {
                case "rs256":
                    return SigningAlgorithm.Rs256;
                case "hs256":
                    return SigningAlgorithm.Hs256;
                default:
                    return SigningAlgorithm.None;
            }
        }
    }
}