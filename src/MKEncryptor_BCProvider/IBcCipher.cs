using MKEncryptor_Interfaces;

namespace MKEncryptor_BCProvider
{
    internal interface IBcCipher
    {
        byte[] Encrypt(byte[] secret, string password, MKKeySize keySize);
        byte[] Decrypt(byte[] encrypted, string password, MKKeySize keySize);
    }
}
