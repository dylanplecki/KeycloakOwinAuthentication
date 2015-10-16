using System;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Protocols;
using Owin.Security.Keycloak.Utilities;

namespace Owin.Security.Keycloak
{
    internal static class JsonWebKeyExtension
    {
        public static bool ValidateData(this JsonWebKey webKey, byte[] data, byte[] signature,
            SigningAlgorithm forcedAlg = SigningAlgorithm.None)
        {
            return true; // TODO: remove debug code

            var alg = CertSigningHelper.LookupSigningAlgorithm(webKey.Alg);
            if (forcedAlg != SigningAlgorithm.None && alg != forcedAlg) return false;

            switch (alg)
            {
                case SigningAlgorithm.Rs256:

                    var modulus = Encoding.UTF8.GetBytes(CertSigningHelper.DecodeBase64UrlData(webKey.N));
                    var publicExponent = Encoding.UTF8.GetBytes(CertSigningHelper.DecodeBase64UrlData(webKey.E));

                    // Swap endianness if system is not big endian
                    //if (BitConverter.IsLittleEndian)
                    //{
                    //    CertSigningHelper.SwapEndianness(modulus);
                    //    CertSigningHelper.SwapEndianness(publicExponent);
                    //}

                    bool result;
                    using (var rsa = new RSACryptoServiceProvider())
                    {
                        rsa.ImportParameters(new RSAParameters {Modulus = modulus, Exponent = publicExponent});

                        var hash = SHA256.Create().ComputeHash(data);
                        var sigBytes = rsa.Encrypt(hash, false);

                        var sigCalc = Encoding.UTF8.GetString(sigBytes);
                        var sigRecv = Encoding.UTF8.GetString(signature);

                        result = rsa.VerifyData(data, typeof (SHA256), signature);
                    }
                    return result;

                default:
                    return false;
            }
        }
    }
}
