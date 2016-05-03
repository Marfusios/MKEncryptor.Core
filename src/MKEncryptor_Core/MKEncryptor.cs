using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MKEncryptor_Core.Helpers;
using MKEncryptor_Core.Models;
using MKEncryptor_Interfaces;

namespace MKEncryptor_Core
{
    public class MKEncryptor
    {
        private readonly MKGroupEncryptionProvider _groupProvider = new MKGroupEncryptionProvider();


        public IEnumerable<IMKEncryptionProvider> EncryptionProviders { get { return _groupProvider.Providers; } }
        public IEnumerable<MKCipherBase> ProvidedCiphers { get { return _groupProvider.ProvidedCiphers; } }

        public string Encrypt(string content, string password, MKCipherBase cipher, MKKeySize keySize = MKKeySize.Key256)
        {
            MKValidationHelper.ValidateInput(content, "content");
            var sourceContent = Encoding.UTF8.GetBytes(content);

            var encrypted = Encrypt(sourceContent, password, cipher, keySize);
            return MKBase64Helper.Encode(encrypted);
        }

        public byte[] Encrypt(byte[] sourceContent, string password, MKCipherBase cipher, MKKeySize keySize = MKKeySize.Key256)
        {
            MKValidationHelper.ValidateInput(sourceContent, "sourceContent");
            MKValidationHelper.ValidateInputNotEmpty(password, "password");
            MKValidationHelper.ValidateInput(cipher, "cipher");
            MKValidationHelper.ValidateSuportedKeySize(cipher, keySize);

            return _groupProvider.Encrypt(sourceContent, password, cipher, keySize);
        }

        public byte[] Encrypt(byte[] sourceContent, string password, MKUsedCipher usedCipher)
        {
            MKValidationHelper.ValidateInput(sourceContent, "sourceContent");
            MKValidationHelper.ValidateInputNotEmpty(password, "password");
            MKValidationHelper.ValidateInput(usedCipher, "usedCipher");

            return Encrypt(sourceContent, password, FindCipherBy(usedCipher), usedCipher.KeySize);
        }

        public void Encrypt(string password, MKEncryptionItem item)
        {
            MKValidationHelper.ValidateInputNotEmpty(password, "password");
            MKValidationHelper.ValidateInput(item, "item");
            MKValidationHelper.ValidateCiphers(item);
            MKValidationHelper.ValidateState(item, MKEncryptionState.Decrypted);

            encryptInCorrectOrder(password, item);
        }


        public string Decrypt(string content, string password, MKCipherBase cipher, MKKeySize keySize = MKKeySize.Key256)
        {
            MKValidationHelper.ValidateInput(content, "content");
            byte[] sourceContent = MKBase64Helper.DecodeToBytes(content);

            var decrypted = Decrypt(sourceContent, password, cipher, keySize);
            return Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);
        }

        public byte[] Decrypt(byte[] sourceContent, string password, MKCipherBase cipher, MKKeySize keySize = MKKeySize.Key256)
        {
            MKValidationHelper.ValidateInput(sourceContent, "sourceContent");
            MKValidationHelper.ValidateInputNotEmpty(password, "password");
            MKValidationHelper.ValidateInput(cipher, "cipher");
            MKValidationHelper.ValidateSuportedKeySize(cipher, keySize);

            return _groupProvider.Decrypt(sourceContent, password, cipher, keySize);
        }

        public byte[] Decrypt(byte[] sourceContent, string password, MKUsedCipher usedCipher)
        {
            MKValidationHelper.ValidateInput(sourceContent, "sourceContent");
            MKValidationHelper.ValidateInputNotEmpty(password, "password");
            MKValidationHelper.ValidateInput(usedCipher, "usedCipher");

            return _groupProvider.Decrypt(sourceContent, password, FindCipherBy(usedCipher), usedCipher.KeySize);
        }

        public void Decrypt(string password, MKEncryptionItem item)
        {
            MKValidationHelper.ValidateInputNotEmpty(password, "password");
            MKValidationHelper.ValidateInput(item, "item");
            MKValidationHelper.ValidateCiphers(item);
            MKValidationHelper.ValidateState(item, MKEncryptionState.Encrypted);

            decryptInCorrectOrder(password, item);
        }

       

        public MKCipherBase FindCipherBy(MKUsedCipher usedCipher)
        {
            return FindCipherBy(usedCipher.UniqueNameCipher, usedCipher.UniqueNameProvider);
        }

        public MKCipherBase FindCipherBy(string cipherUniqueName, string providerUniqueName)
        {
            var cipher = ProvidedCiphers.FirstOrDefault(x =>
                x.UniqueName.Equals(cipherUniqueName) &&
                x.Provider.UniqueName.Equals(providerUniqueName));
            if (cipher != null)
                return cipher;
            throw new MKException(string.Format("There is no provided cipher for input: [Cipher: {0} | Provider: {1}]",
                cipherUniqueName, providerUniqueName));
        }

        private void encryptInCorrectOrder(string password, MKEncryptionItem item)
        {
            byte[] result = item.Content;
            var ordered = item.UsedCiphers.OrderBy(x => x.Index).ToList();
            foreach (var usedCipher in ordered)
            {
                result = Encrypt(result, password, usedCipher);
            }
            item.Content = result;
            item.State = MKEncryptionState.Encrypted;
            item.LastModified = DateTime.Now;
        }

        private void decryptInCorrectOrder(string password, MKEncryptionItem item)
        {
            byte[] result = item.Content;
            var ordered = item.UsedCiphers.OrderByDescending(x => x.Index).ToList();
            foreach (var usedCipher in ordered)
            {
                result = Decrypt(result, password, usedCipher);
            }
            item.Content = result;
            item.State = MKEncryptionState.Decrypted;
            item.LastModified = DateTime.Now;
        }

    }
}
