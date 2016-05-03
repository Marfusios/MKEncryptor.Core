using System;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider.Ciphers
{
    class DesCipher: BcCipher<DesEngine>
    {
        public DesCipher(IMKEncryptionProvider provider)
            : base(provider)
        {
        }

        public override string UniqueName
        {
            get { return "des"; }
        }

        public override string DisplayName
        {
            get { return "DES"; }
        }

        public override string Description
        {
            get
            {
                return string.Format("The Data Encryption Standard (DES) was once a predominant symmetric-key algorithm for the encryption of electronic data. " +
                                     "It was highly influential in the advancement of modern cryptography in the academic world. " +
                                     "Developed in the early 1970s at IBM and based on an earlier design by Horst Feistel, " +
                                     "the algorithm was submitted to the National Bureau of Standards (NBS) following the agency's invitation to propose a candidate for the protection of sensitive, " +
                                     "unclassified electronic government data. In 1976, after consultation with the National Security Agency (NSA), " +
                                     "the NBS eventually selected a slightly modified version (strengthened against differential cryptanalysis, but weakened against brute force attacks), " +
                                     "which was published as an official Federal Information Processing Standard (FIPS) for the United States in 1977. {0}{0}" +
                                     "The publication of an NSA-approved encryption standard simultaneously resulted in its quick international adoption and widespread academic scrutiny. " +
                                     "Controversies arose out of classified design elements, a relatively short key length of the symmetric-key block cipher design, and the involvement of the NSA, " +
                                     "nourishing suspicions about a backdoor. The intense academic scrutiny the algorithm received over time led to the modern understanding of block ciphers and their cryptanalysis."
                                     , Environment.NewLine);
            }
        }

        public override string DescriptionLink
        {
            get { return "https://en.wikipedia.org/wiki/Data_Encryption_Standard"; }
        }
    }
}
