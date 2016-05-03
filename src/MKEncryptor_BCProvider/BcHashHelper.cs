using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace MKEncryptor_BCProvider
{
    public static class BcHashHelper
    {
        public static byte[] ComputeSha1(Encoding encoding, string key)
        {
            return computeHash<Sha1Digest>(encoding, key);
        }

        public static byte[] ComputeSha256(Encoding encoding, string key)
        {
            return computeHash<Sha256Digest>(encoding, key);
        }

        public static byte[] ComputeSha512(Encoding encoding, string key)
        {
            return computeHash<Sha512Digest>(encoding, key);
        }

        public static byte[] ComputeSha1(byte[] key)
        {
            return computeHash<Sha1Digest>(key);
        }

        public static byte[] ComputeSha256(byte[] key)
        {
            return computeHash<Sha256Digest>(key);
        }

        public static byte[] ComputeSha512(byte[] key)
        {
            return computeHash<Sha512Digest>(key);
        }


        private static byte[] computeHash<T>(Encoding encoding, string key) where T : IDigest, new()
        {
            var bytes = encoding.GetBytes(key);
            return computeHash<T>(bytes);
        }

        private static byte[] computeHash<T>(byte[] key) where T : IDigest, new()
        {
            var digester = new T();
            var retValue = new byte[digester.GetDigestSize()];
            digester.BlockUpdate(key, 0, key.Length);
            digester.DoFinal(retValue, 0);
            return retValue;
        }
    }
}
