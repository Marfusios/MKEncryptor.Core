using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace MKEncryptor_Interfaces
{
    public abstract class MKEncryptionProviderBase : IMKEncryptionProvider
    {
        public abstract string UniqueName { get; }
        public abstract string DisplayName { get; }
        protected abstract HashSet<MKCipherBase> RegisterProvidedCiphersInternal { get; }
        public abstract string Description { get; }
        public abstract string DescriptionLink { get; }

        public byte[] Encrypt(byte[] secret, string password, MKCipherBase cipher, MKKeySize keySize)
        {
            checkContainCipher(cipher);
            return EncryptInternal(secret, password, cipher, keySize);
        }

        public byte[] Decrypt(byte[] encrypted, string password, MKCipherBase cipher, MKKeySize keySize)
        {
            checkContainCipher(cipher);
            return DecryptInternal(encrypted, password, cipher, keySize);
        }

        public IReadOnlyCollection<MKCipherBase> ProvidedCiphers
        {
            get
            {
                var ciphers = RegisterProvidedCiphersInternal;
                checkNotNullOrEmpty(ciphers);
                checkCiphersState(ciphers);
                return new ReadOnlyCollection<MKCipherBase>(ciphers.ToList());
            }
        }


        protected abstract byte[] EncryptInternal(byte[] secret, string password, MKCipherBase cipher, MKKeySize keySize);
        protected abstract byte[] DecryptInternal(byte[] encrypted, string password, MKCipherBase cipher, MKKeySize keySize);


        private void checkContainCipher(MKCipherBase cipher)
        {
            if (!ProvidedCiphers.Contains(cipher))
                throw new MKException(string.Format("This provider doesn't provide requested cipher ({0})", cipher));
        }

        private void checkNotNullOrEmpty(HashSet<MKCipherBase> ciphers)
        {
            if (ciphers == null)
                throw new MKException("Provided ciphers can't be null");
            if (ciphers.Count <= 0)
                throw new MKException("Provider must at least provide one cipher");
        }

        private void checkCiphersState(HashSet<MKCipherBase> ciphers)
        {
            foreach (MKCipherBase cipher in ciphers)
            {
                cipher.CheckCipherState();
            }
        }
    }
}