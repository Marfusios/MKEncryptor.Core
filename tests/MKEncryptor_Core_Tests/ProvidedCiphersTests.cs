using System.Linq;
using System.Text;
using MKEncryptor_Core;
using MKEncryptor_Interfaces;
using NUnit.Framework;

namespace MKEncryptor_Core_Tests
{
    [TestFixture]
    class ProvidedCiphersTests
    {
        [Test]
        public void GetProvidedCiphers()
        {
            var encryptor = new MKEncryptor();
            var ciphers = encryptor.ProvidedCiphers;

            Assert.NotNull(ciphers);
            Assert.True(ciphers.Any());
        }

        [Test]
        public void EncryptDecryptWithAllCiphers_128()
        {
            testAllCiphers("test one msg", MKKeySize.Key128);
        }

        [Test]
        public void EncryptDecryptWithAllCiphers_192()
        {
            testAllCiphers("test one msg", MKKeySize.Key192);
        }

        [Test]
        public void EncryptDecryptWithAllCiphers_256()
        {
            testAllCiphers("test one msg", MKKeySize.Key256);
        }

        [Test]
        public void EncryptDecryptWithAllCiphers_256_CZ()
        {
            testAllCiphers("test česká zpráva čřě éíěš ¨§)ů) ¨¨ §§)úů", MKKeySize.Key256);
        }

        [Test]
        public void EncryptDecryptWithAllCiphers_256_String()
        {
            testAllCiphers("test one msg", MKKeySize.Key256, true);
        }


        [Test]
        public void EncryptDecryptWithAllCiphers_512()
        {
            testAllCiphers("test one msg", MKKeySize.Key512);
        }

        private static void testAllCiphers(string input, MKKeySize keySize, bool byString = false)
        {
            var encryptorOne = new MKEncryptor();
            var encryptorTwo = new MKEncryptor();
            var ciphers = encryptorOne.ProvidedCiphers;

            foreach (var cipher in ciphers)
            {
                if(!cipher.SupportedKeySizes.Contains(keySize))
                    continue;

                if (byString)
                {
                    var password = "some my secret password";

                    var encrypted = encryptorOne.Encrypt(input, password, cipher, keySize);
                    var decrypted = encryptorTwo.Decrypt(encrypted, password, cipher, keySize);

                    Assert.AreEqual(input, decrypted);
                }
                else
                {
                    var msg = Encoding.UTF8.GetBytes(input);
                    var password = "some my secret password";

                    var encrypted = encryptorOne.Encrypt(msg, password, cipher, keySize);
                    var decrypted = encryptorTwo.Decrypt(encrypted, password, cipher, keySize);

                    Assert.AreEqual(msg, decrypted);
                }
                
            }
        }
    }
}
