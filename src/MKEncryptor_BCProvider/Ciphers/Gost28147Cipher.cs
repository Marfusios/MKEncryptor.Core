using System;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider.Ciphers
{
    internal class Gost28147Cipher : BcCipher<Gost28147Engine>
    {
        public Gost28147Cipher(IMKEncryptionProvider provider)
            : base(provider)
        {
        }

        public override string UniqueName
        {
            get { return "gost28147"; }
        }

        public override string DisplayName
        {
            get { return "Gost28147"; }
        }

        public override string Description
        {
            get
            {
                return string.Format("The GOST block cipher, defined in the standard GOST 28147-89, is a Soviet and Russian government standard symmetric key block cipher. " +
                                     "Also based on this block cipher is the GOST hash function. {0}{0}" +
                                     "Developed in the 1970s, the standard had been marked 'Top Secret' and then downgraded to 'Secret' in 1990. " +
                                     "Shortly after the dissolution of the USSR, it was declassified and it was released to the public in 1994. " +
                                     "GOST 28147 was a Soviet alternative to the United States standard algorithm, DES. Thus, the two are very similar in structure."
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://en.wikipedia.org/wiki/GOST_(block_cipher)"; }
        }

        public override MKKeySize[] SupportedKeySizes
        {
            get { return new[] {MKKeySize.Key256 }; }
        }
    }
}