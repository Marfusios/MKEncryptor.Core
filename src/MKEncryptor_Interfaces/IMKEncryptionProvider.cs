using System.Collections.Generic;

namespace MKEncryptor_Interfaces
{
    public interface IMKEncryptionProvider
    {
        string UniqueName { get; }
        string DisplayName { get; }
        byte[] Encrypt(byte[] secret, string password, MKCipherBase cipher, MKKeySize keySize);
        byte[] Decrypt(byte[] encrypted, string password, MKCipherBase cipher, MKKeySize keySize);

        IReadOnlyCollection<MKCipherBase> ProvidedCiphers { get; }

        string Description { get; }
        string DescriptionLink { get; }
    }
}
