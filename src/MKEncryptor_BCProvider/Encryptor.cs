using System;
using System.Text;
using MKEncryptor_Interfaces;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace MKEncryptor_BCProvider
{


    internal sealed class Encryptor<TBlockCipher, TDigest>
        where TBlockCipher : IBlockCipher, new()
        where TDigest : IDigest, new()
    {
        public static readonly Encoding DEFAULT_ENCODING = Encoding.UTF8;
        private const int MIN_PASSWORD_LENGTH = 8;
        public const int SALT_BYTE_SIZE = 16; // 128bit

        private readonly SecureRandom _random = new SecureRandom();
        private readonly Encoding _encoding;
        private IBlockCipher _blockCipher;
        private BufferedBlockCipher _cipher;
        private HMac _mac;
        private readonly string _keyString;

        public Encryptor(Encoding encoding, string password, IBlockCipherPadding padding, MKKeySize keySize)
        {
            KeySize = keySize;
            _encoding = encoding;
            _keyString = password;
            init(padding);
        }

        public Encryptor(string password, MKKeySize keySize) :
            this(DEFAULT_ENCODING, password, new Pkcs7Padding(), keySize)
        {
        }


        public MKKeySize KeySize { get; private set; }


        public string Encrypt(string plain)
        {
            return Convert.ToBase64String(EncryptBytes(plain));
        }

        public string Encrypt(byte[] plain)
        {
            var result = EncryptBytes(plain);
            return _encoding.GetString(result, 0, result.Length);
        }

        public byte[] EncryptBytes(string plain)
        {
            byte[] input = _encoding.GetBytes(plain);
            return EncryptBytes(input);
        }

        public byte[] EncryptBytes(byte[] input)
        {
            var iv = generateIV();
            byte[] salt = generateSalt();
            KeyParameter keyParam;
            KeyParameter macParam;

            generateKey(_keyString, salt, out keyParam, out macParam);
            initMac(macParam);

            var cipher = bouncyCastleCrypto(true, input, 
                new ParametersWithIV(keyParam, iv));
            byte[] ivWithSalt = combineArrays(iv, salt);
            byte[] message = combineArrays(ivWithSalt, cipher);

            _mac.Reset();
            _mac.BlockUpdate(message, 0, message.Length);
            byte[] digest = new byte[_mac.GetUnderlyingDigest().GetDigestSize()];
            _mac.DoFinal(digest, 0);

            var result = combineArrays(digest, message);
            return result;
        }

        public byte[] DecryptBytes(byte[] bytes)
        {
            // split the digest into component parts
            var digest = new byte[_mac.GetUnderlyingDigest().GetDigestSize()];
            if(digest.Length >= bytes.Length)
                throw new MKException(string.Format("Encrypted message is too short. Current size: {0}B. HMAC size: {1}B", 
                    bytes.Length, digest.Length));

            var message = new byte[bytes.Length - digest.Length];
            var iv = new byte[_blockCipher.GetBlockSize()];
            var salt = new byte[SALT_BYTE_SIZE];
            var cipher = new byte[message.Length - iv.Length - salt.Length];

            Buffer.BlockCopy(bytes, 0, digest, 0, digest.Length);
            Buffer.BlockCopy(bytes, digest.Length, message, 0, message.Length);
            Buffer.BlockCopy(message, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(message, iv.Length, salt, 0, salt.Length);

            KeyParameter keyParam;
            KeyParameter macParam;

            generateKey(_keyString, salt, out keyParam, out macParam);
            initMac(macParam);

            if (!isValidHMac(digest, message))
            {
                throw new MKException("Password is incorrect or authentication failed (HMAC)");
            }

            Buffer.BlockCopy(message, iv.Length + salt.Length, cipher, 0, cipher.Length);

            

            byte[] result = bouncyCastleCrypto(false, cipher, 
                new ParametersWithIV(keyParam, iv));
            return result;
        }

        public string Decrypt(byte[] bytes)
        {
            var decrypted = DecryptBytes(bytes);
            return _encoding.GetString(decrypted, 0, decrypted.Length);
        }

        public string Decrypt(string cipher)
        {
            return Decrypt(Convert.FromBase64String(cipher));
        }





        private void init(IBlockCipherPadding padding)
        {
            _blockCipher = new CbcBlockCipher(new TBlockCipher());
            _cipher = new PaddedBufferedBlockCipher(_blockCipher, padding);
            _mac = new HMac(new TDigest());
        }

        private void initMac(KeyParameter macParam)
        {
            _mac.Init(macParam);
        }

        private bool isValidHMac(byte[] digest, byte[] message)
        {
            _mac.Reset();
            _mac.BlockUpdate(message, 0, message.Length);
            byte[] computed = new byte[_mac.GetUnderlyingDigest().GetDigestSize()];
            _mac.DoFinal(computed, 0);

            return areEqual(digest, computed);
        }

        private static bool areEqual(byte[] digest, byte[] computed)
        {
            if (digest.Length != computed.Length)
            {
                return false;
            }

            int result = 0;
            for (int i = 0; i < digest.Length; i++)
            {
                result |= digest[i] ^ computed[i];
            }

            return result == 0;
        }

        private byte[] bouncyCastleCrypto(bool forEncrypt, byte[] input, ICipherParameters parameters)
        {
            try
            {
                _cipher.Init(forEncrypt, parameters);
                return _cipher.DoFinal(input);
            }
            catch (CryptoException ex)
            {
                throw new MKException(
                    string.Format("Crypto exception while {0} bytes. Exception: {1}", forEncrypt ? "encrypting" : "decrypting", ex.Message), ex);
            }
        }

        private byte[] generateIV()
        {        
            // 1st block
            byte[] result = new byte[_blockCipher.GetBlockSize()];
            _random.NextBytes(result);

            return result;    
        }

        private void generateKey(string password, byte[] salt, out KeyParameter encryptionKey, out KeyParameter macKey)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < MIN_PASSWORD_LENGTH)
                throw new MKException(string.Format("Must have a password of at least {0} characters!", MIN_PASSWORD_LENGTH));

            var generator = new Pkcs5S2ParametersGenerator();
            generator.Init(
                PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()),
                salt, 
                13333);

            //Generate Key
            var keySize = (int) KeySize;
            var keySizeBytes = keySize/8;
            var bigKeySize = keySize * 2;
            var bigKey = (KeyParameter)generator.GenerateDerivedMacParameters(bigKeySize);
            var bigKeyExact = bigKey.GetKey();

            var encryptionKeyExact = new byte[keySizeBytes];
            var macKeyExact = new byte[keySizeBytes];

            Buffer.BlockCopy(bigKeyExact, 0, encryptionKeyExact, 0, keySizeBytes);
            Buffer.BlockCopy(bigKeyExact, keySizeBytes, macKeyExact, 0, keySizeBytes);

            encryptionKey = new KeyParameter(encryptionKeyExact);
            macKey = new KeyParameter(macKeyExact);
        }

        private byte[] generateSalt()
        {
            var salt = new byte[SALT_BYTE_SIZE];
            _random.NextBytes(salt);
            return salt;
        }

        private static byte[] combineArrays(byte[] source1, byte[] source2)
        {
            byte[] result = new byte[source1.Length + source2.Length];
            Buffer.BlockCopy(source1, 0, result, 0, source1.Length);
            Buffer.BlockCopy(source2, 0, result, source1.Length, source2.Length);

            return result;
        }
    }
}
