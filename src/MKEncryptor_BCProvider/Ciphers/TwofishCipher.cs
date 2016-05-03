using System;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider.Ciphers
{
    class TwofishCipher : BcCipher<TwofishEngine>
    {
        public TwofishCipher(IMKEncryptionProvider provider) : base(provider)
        {
        }

        public override string UniqueName
        {
            get { return "twofish"; }
        }

        public override string DisplayName
        {
            get { return "TwoFish"; }
        }

        public override string Description
        {
            get
            {
                return string.Format("In cryptography, Twofish is a symmetric key block cipher with a block size of 128 bits and key sizes up to 256 bits. " +
                                     "It was one of the five finalists of the Advanced Encryption Standard contest, but it was not selected for standardization. " +
                                     "Twofish is related to the earlier block cipher Blowfish. {0}{0}" +
                                     "On most software platforms Twofish was slightly slower than Rijndael (AES) for 128-bit keys, but it is somewhat faster for 256-bit keys. {0}{0}" +
                                     "The Twofish cipher has not been patented and the reference implementation has been placed in the public domain. " +
                                     "As a result, the Twofish algorithm is free for anyone to use without any restrictions whatsoever. " +
                                     "It is one of a few ciphers included in the OpenPGP standard (RFC 4880). " +
                                     "However, Twofish has seen less widespread usage than Blowfish, which has been available longer."
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://en.wikipedia.org/wiki/Twofish"; }
        }
    }
}
