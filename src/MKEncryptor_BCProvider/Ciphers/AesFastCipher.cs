using System;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider.Ciphers
{
    class AesFastCipher : BcCipher<AesFastEngine>
    {
        public AesFastCipher(IMKEncryptionProvider provider) : base(provider)
        {
        }

        public override string UniqueName
        {
            get { return "aes_fast"; }
        }

        public override string DisplayName
        {
            get { return "AES fast"; }
        }

        public override string Description
        {
            get
            {
                return string.Format("The Advanced Encryption Standard (AES), also known as Rijndael (its original name), " +
                                     "is a specification for the encryption of electronic data established by the U.S. " +
                                     "National Institute of Standards and Technology (NIST) in 2001. {0}{0}" +
                                     "AES is based on the Rijndael cipher developed by two Belgian cryptographers, " +
                                     "Joan Daemen and Vincent Rijmen, who submitted a proposal to NIST during the AES selection process. " +
                                     "Rijndael is a family of ciphers with different key and block sizes. {0}{0}" +
                                     "AES has been adopted by the U.S. government and is now used worldwide. " +
                                     "It supersedes the Data Encryption Standard (DES), which was published in 1977. " +
                                     "The algorithm described by AES is a symmetric-key algorithm, " +
                                     "meaning the same key is used for both encrypting and decrypting the data."
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://en.wikipedia.org/wiki/Advanced_Encryption_Standard"; }
        }
    }
}
