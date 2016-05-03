using System;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider.Ciphers
{
    class BlowfishCipher : BcCipher<BlowfishEngine>
    {
        public BlowfishCipher(IMKEncryptionProvider provider) : base(provider)
        {
        }

        public override string UniqueName
        {
            get { return "blowfish"; }
        }

        public override string DisplayName
        {
            get { return "BlowFish"; }
        }

        public override string Description
        {
            get
            {
                return string.Format("Blowfish is a symmetric-key block cipher, designed in 1993 by Bruce Schneier " +
                                     "and included in a large number of cipher suites and encryption products. " +
                                     "Blowfish provides a good encryption rate in software and no effective cryptanalysis of it has been found to date. " +
                                     "However, the Advanced Encryption Standard (AES) now receives more attention. {0}{0}" +
                                     "Schneier designed Blowfish as a general-purpose algorithm,. " +
                                     "intended as an alternative to the aging DES and free of the problems and constraints associated with other algorithms.. " +
                                     "At the time Blowfish was released, many other designs were proprietary, encumbered by patents or were commercial or government secrets.. " +
                                     "Schneier has stated that, 'Blowfish is unpatented, and will remain so in all countries.The algorithm is hereby placed in the public domain,. " +
                                     "and can be freely used by anyone.'"
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://en.wikipedia.org/wiki/Blowfish_(cipher)"; }
        }
    }
}
