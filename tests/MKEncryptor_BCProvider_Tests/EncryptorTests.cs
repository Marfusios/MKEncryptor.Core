using System.Text;
using MKEncryptor_BCProvider;
using MKEncryptor_Interfaces;
using NUnit.Framework;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;

namespace MKEncryptor_BCProvider_Tests
{
    [TestFixture]
    public class EncryptorTests
    {
        [Test]
        public void EncryptDecryptEncryptor()
        {
            var msg = "testOne";
            var pass = "mkmkmkmkmkmk";
            var encryptor = new Encryptor<AesEngine, Sha256Digest>(pass, MKKeySize.Key256);

            var encrypted = encryptor.Encrypt(msg);
            var decrypted = encryptor.Decrypt(encrypted);

            Assert.AreEqual(msg, decrypted);
        }

        [Test]
        public void EncryptDecryptEncryptor_HMAC()
        {
            var msg = "testOne";
            var pass = "mkmkmkmkmkmk";
            var encryptor = new Encryptor<AesEngine, Sha256Digest>(pass, MKKeySize.Key256);

            var encrypted = encryptor.Encrypt(msg);
            var decrypted = encryptor.Decrypt(encrypted);

            Assert.AreEqual(msg, decrypted);
        }


        [Test]
        public void EncryptDecryptEncryptor_CZ()
        {
            var msg = "testOne české znaky éíščřž+8;+§§ůú¨ů";
            var pass = "mkmkmkmkmkmk";
            var encryptor = new Encryptor<AesEngine, Sha256Digest>(pass, MKKeySize.Key256);

            var encrypted = encryptor.Encrypt(msg);
            var decrypted = encryptor.Decrypt(encrypted);

            Assert.AreEqual(msg, decrypted);
        }


        [Test]
        public void EncryptDecryptEncryptor_HMAC_CZ()
        {
            var msg = "testOne české znaky éíščřž+8;+§§ůú¨ů";
            var pass = "mkmkmkmkmkmk";
            var encryptor = new Encryptor<AesEngine, Sha256Digest>(pass, MKKeySize.Key256);

            var encrypted = encryptor.Encrypt(msg);
            var decrypted = encryptor.Decrypt(encrypted);

            Assert.AreEqual(msg, decrypted);
        }


        


        [Test]
        public void EncryptDecryptTwoEncryptors_HMAC()
        {
            var msg = "testOne";
            var pass = "mkmkmkmkmkmk";

            var encryptorOne = new Encryptor<AesEngine, Sha256Digest>(pass, MKKeySize.Key256);
            var encryptorTwo = new Encryptor<AesEngine, Sha256Digest>(pass, MKKeySize.Key256);

            var encrypted = encryptorOne.Encrypt(msg);
            var decrypted = encryptorTwo.Decrypt(encrypted);

            Assert.AreEqual(msg, decrypted);
        }

    }
}
