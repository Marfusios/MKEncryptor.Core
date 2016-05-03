using MKEncryptor_Interfaces;
using Newtonsoft.Json;

namespace MKEncryptor_Core.Models
{
    public class MKUsedCipher
    {
        [JsonConstructor]
        public MKUsedCipher(int index, string uniqueNameCipher, string uniqueNameProvider, MKKeySize keySize)
        {
            KeySize = keySize;
            Index = index;
            UniqueNameCipher = uniqueNameCipher;
            UniqueNameProvider = uniqueNameProvider;
        }

        public MKUsedCipher(string uniqueNameCipher, string uniqueNameProvider, MKKeySize keySize)
        {
            KeySize = keySize;
            Index = 0;
            UniqueNameCipher = uniqueNameCipher;
            UniqueNameProvider = uniqueNameProvider;
        }

        public int Index { get; set; }
        public string UniqueNameCipher { get; private set; }
        public string UniqueNameProvider { get; private set; }
        public MKKeySize KeySize { get; set; }

        public static MKUsedCipher CreateFrom(MKCipherBase cipher, int index, MKKeySize keySize)
        {
            return new MKUsedCipher(index, cipher.UniqueName, cipher.Provider.UniqueName, keySize);
        }

        public static MKUsedCipher CreateFrom(MKCipherBase cipher, MKKeySize keySize)
        {
            return CreateFrom(cipher, 0, keySize);
        }

        public override string ToString()
        {
            return string.Format("{0} ({1})", UniqueNameCipher, (int) KeySize);
        }
    }
}
