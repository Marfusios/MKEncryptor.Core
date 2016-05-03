using System.Linq;
using MKEncryptor_Core.Models;
using MKEncryptor_Interfaces;

namespace MKEncryptor_Core.Helpers
{
    public static class MKValidationHelper
    {
        public static void ValidateInput(object val, string name)
        {
            if (val == null)
                throw new MKException(string.Format("Parameter {0} is null", name));
        }

        public static void ValidateInputNotEmpty(object val, string name)
        {
            if (val == null || string.IsNullOrWhiteSpace(val.ToString()))
                throw new MKException(string.Format("Parameter {0} must be set", name));
        }


        public static void ValidateState(MKEncryptionItem item, MKEncryptionState expectedState)
        {
            if (item.State != expectedState)
                throw new MKException(string.Format("Item ({0}) is not in valid state", item));
        }

        public static void ValidateCiphers(MKEncryptionItem item)
        {
            if (item.UsedCiphers == null || item.UsedCiphers.Count <= 0)
                throw new MKException(string.Format("Item ({0}) has not specified cipher/ciphers", item));
        }

        public static void ValidateSuportedKeySize(MKCipherBase cipher, MKKeySize keySize)
        {
            if(!cipher.SupportedKeySizes.Contains(keySize))
                throw new MKException(string.Format("Cipher {0} does not support key size: {1}. Supported key sizes are: {2}",
                    cipher.DisplayName, (int)keySize, MKEnumerableHelper.ArrayToString(cipher.SupportedKeySizes)));
        }

       
    }
}
