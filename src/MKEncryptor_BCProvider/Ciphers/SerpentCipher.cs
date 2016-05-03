using System;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider.Ciphers
{
    class SerpentCipher : BcCipher<SerpentEngine>
    {
        public SerpentCipher(IMKEncryptionProvider provider) : base(provider)
        {
        }

        public override string UniqueName
        {
            get { return "serpent"; }
        }

        public override string DisplayName
        {
            get { return "Serpent"; }
        }

        public override string Description
        {
            get
            {
                return string.Format("Serpent is a symmetric key block cipher that was a finalist in the Advanced Encryption Standard (AES) contest, " +
                                     "where it was ranked second to Rijndael. Serpent was designed by Ross Anderson, Eli Biham, and Lars Knudsen. {0}{0}" +
                                     "Like other AES submissions, Serpent has a block size of 128 bits and supports a key size of 128, 192 or 256 bits. " +
                                     "The cipher is a 32-round substitution-permutation network operating on a block of four 32-bit words. " +
                                     "Each round applies one of eight 4-bit to 4-bit S-boxes 32 times in parallel. " +
                                     "Serpent was designed so that all operations can be executed in parallel, using 32 bit slices. " +
                                     "This maximizes parallelism, but also allows use of the extensive cryptanalysis work performed on DES. {0}{0}" +
                                     "Serpent took a conservative approach to security, opting for a large security margin: " +
                                     "the designers deemed 16 rounds to be sufficient against known types of attack, " +
                                     "but specified 32 rounds as insurance against future discoveries in cryptanalysis. " +
                                     "The official NIST report on AES competition classified Serpent as having a high security margin along with MARS and Twofish, " +
                                     "in contrast to the adequate security margin of RC6 and Rijndael (currently AES). In final voting, " +
                                     "Serpent had the least number of negative votes among the finalists, but scored second place overall because Rijndael had substantially more positive votes, " +
                                     "the deciding factor being that Rijndael allowed for a far more efficient software implementation."
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://en.wikipedia.org/wiki/Serpent_(cipher)"; }
        }
    }
}
