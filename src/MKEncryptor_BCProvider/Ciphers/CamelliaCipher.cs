using System;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider.Ciphers
{
    class CamelliaCipher : BcCipher<CamelliaEngine>
    {
        public CamelliaCipher(IMKEncryptionProvider provider)
            : base(provider)
        {
        }

        public override string UniqueName
        {
            get { return "camellia"; }
        }

        public override string DisplayName
        {
            get { return "Camellia"; }
        }

        public override string Description
        {
            get
            {
                return string.Format("In cryptography, Camellia is a symmetric key block cipher with a block size of 128 bits " +
                                     "and key sizes of 128, 192 and 256 bits. It was jointly developed by Mitsubishi and NTT of Japan. " +
                                     "The cipher has been approved for use by the ISO/IEC, the European Union's NESSIE project and the Japanese CRYPTREC project. " +
                                     "The cipher has security levels and processing abilities comparable to the Advanced Encryption Standard. {0}{0}" +
                                     "The cipher was designed to be suitable for both software and hardware implementations, from low-cost smart cards to high-speed network systems. " +
                                     "It is part of the Transport Layer Security (TLS), cryptographic protocol designed to provide communications security over a computer network such as the internet."
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://en.wikipedia.org/wiki/Camellia_(cipher)"; }
        }
    }
}
