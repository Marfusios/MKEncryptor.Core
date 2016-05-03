using System;
using System.Collections.Generic;
using MKEncryptor_BCProvider.Ciphers;
using MKEncryptor_Interfaces;

namespace MKEncryptor_BCProvider
{
    public class MKBouncyCastleProvider : MKEncryptionProviderBase
    {
        public override string UniqueName
        {
            get { return "bouncy_castle"; }
        }

        public override string DisplayName
        {
            get { return "Bouncy castle"; }
        }

        protected override byte[] EncryptInternal(byte[] secret, string password, MKCipherBase cipher, MKKeySize keySize)
        {
            checkIfCorrectCipher(cipher);
            var bcCipher = (IBcCipher) cipher;
            return bcCipher.Encrypt(secret, password, keySize);
        }

        protected override byte[] DecryptInternal(byte[] encrypted, string password, MKCipherBase cipher, MKKeySize keySize)
        {
            checkIfCorrectCipher(cipher);
            var bcCipher = (IBcCipher) cipher;
            return bcCipher.Decrypt(encrypted, password, keySize);
        }

        private void checkIfCorrectCipher(MKCipherBase cipher)
        {
            var bcCipher = cipher as IBcCipher;
            if (bcCipher == null)
                throw new MKException(string.Format("Cipher is incorrect (not from {0} provider)", DisplayName));
        }


        // HERE register all ciphers
        protected override HashSet<MKCipherBase> RegisterProvidedCiphersInternal
        {
            get
            {
                return new HashSet<MKCipherBase>
                {
                    new AesCipher(this),
                    new AesFastCipher(this),
                    new BlowfishCipher(this),
                    new TwofishCipher(this),
                    new SerpentCipher(this),
                    new DesCipher(this),
                    new RijndaelCipher(this),
                    new CamelliaCipher(this),
                    new Gost28147Cipher(this)
                };
            }
        }

        public override string Description
        {
            get
            {
                return string.Format("Bouncy Castle is a collection of APIs used in cryptography. It includes APIs for both the Java and the C# programming languages. " +
                                     "The APIs are supported by a registered Australian charitable organization: Legion of the Bouncy Castle Inc. {0}{0}" +
                                     "Bouncy Castle is Australian in origin and therefore American restrictions on the export of cryptographic software do not apply to it." 
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://www.bouncycastle.org/"; }
        }
    }
}