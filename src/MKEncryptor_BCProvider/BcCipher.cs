using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;

namespace MKEncryptor_BCProvider
{
    internal abstract class BcCipher<TBlockCipher> : MKCipherBase, IBcCipher
        where TBlockCipher : IBlockCipher, new()
    {
        private readonly IMKEncryptionProvider _provider;

        public BcCipher(IMKEncryptionProvider provider)
        {
            _provider = provider;
        }

        public byte[] Encrypt(byte[] secret, string password, MKKeySize keySize)
        {
            var encryptor = new Encryptor<TBlockCipher, Sha512Digest>(password, keySize);
            return encryptor.EncryptBytes(secret);
        }

        public byte[] Decrypt(byte[] encrypted, string password, MKKeySize keySize)
        {
            var encryptor = new Encryptor<TBlockCipher, Sha512Digest>(password, keySize);
            return encryptor.DecryptBytes(encrypted);
        }

        public override IMKEncryptionProvider Provider { get { return _provider; } }
    }
}
