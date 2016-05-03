using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using MKEncryptor_BCProvider;
using MKEncryptor_Interfaces;

namespace MKEncryptor_Core
{
    class MKGroupEncryptionProvider : MKEncryptionProviderBase
    {
        private readonly List<IMKEncryptionProvider> _providers = new List<IMKEncryptionProvider>();

        public MKGroupEncryptionProvider()
        {
            registerProviders();
        }

        public IReadOnlyCollection<IMKEncryptionProvider> Providers
        {
            get { return new ReadOnlyCollection<IMKEncryptionProvider>(_providers); }
        }

        public override string UniqueName
        {
            get { return "group_of_providers"; }
        }

        public override string DisplayName
        {
            get { return "Group of available encryption providers"; }
        }

        protected override byte[] EncryptInternal(byte[] secret, string password, MKCipherBase cipher, MKKeySize keySize)
        {
            return getProviderByCipher(cipher).Encrypt(secret, password, cipher, keySize);
        }

        protected override byte[] DecryptInternal(byte[] encrypted, string password, MKCipherBase cipher, MKKeySize keySize)
        {
            return getProviderByCipher(cipher).Decrypt(encrypted, password, cipher, keySize);
        }

        protected override HashSet<MKCipherBase> RegisterProvidedCiphersInternal
        {
            get
            {
                var result = new HashSet<MKCipherBase>();
                foreach (var provider in _providers)
                {
                    foreach (var cipher in provider.ProvidedCiphers)
                    {
                        result.Add(cipher);
                    }
                }
                return result;
            }
        }

        public override string Description
        {
            get { throw new NotSupportedException(); }
        }

        public override string DescriptionLink
        {
            get { throw new NotSupportedException(); }
        }

        private IMKEncryptionProvider getProviderByCipher(MKCipherBase cipher)
        {
            foreach (var provider in _providers)
            {
                if (provider.ProvidedCiphers.Contains(cipher))
                    return provider;
            }
            throw new MKException(string.Format("There is no provider for requested cipher: {0}", cipher));
        }



        // HERE register all providers
        private void registerProviders()
        {
            _providers.Add(new MKBouncyCastleProvider());
        }

        
    }
}
