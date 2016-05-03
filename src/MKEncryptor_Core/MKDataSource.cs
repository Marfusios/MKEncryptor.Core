using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MKEncryptor_Core.Models;
using MKEncryptor_Interfaces;
using Newtonsoft.Json;

namespace MKEncryptor_Core
{
    internal class MKDataSource
    {
        // TODO: Make it configurable
        private const string GLOBAL_APP_PASS =
            "some secret loooong password dkjg nrkgnkdrngkdnrgkndgndrgndkgndfg dfgn dgfndkfn gkdn rgknkd gndkn gkd gn drgkndkgn rkn'sklg'rl gl";

        private static MKEncryptor _internalEncryptor = new MKEncryptor();
        private static MKCipherBase _internalCipher;

        public const string FILES_KEY = "mk_files";
        public const string DIRS_KEY = "mk_dirs";
        public const string TEXTS_KEY = "mk_texts";

        public const string DEFAULT_USED_CIPHERS = "mk_used_ciphers_default";

        private readonly IMKRawDataProvider _rawDataProvider;

        static MKDataSource()
        {
            initDefaultCipher();
        }

        public MKDataSource(IMKRawDataProvider rawDataProvider)
        {
            _rawDataProvider = rawDataProvider;
        }



        public async Task<IEnumerable<MKEncryptionFile>> GetEncryptionFiles()
        {
            return await getItems<MKEncryptionFile>(FILES_KEY);
        }

        public async Task<IEnumerable<MKEncryptionDir>> GetEncryptionDirs()
        {
            return await getItems<MKEncryptionDir>(DIRS_KEY);
        }

        public async Task<IEnumerable<MKEncryptionText>> GetEncryptionTexts()
        {
            return await getItems<MKEncryptionText>(TEXTS_KEY);
        }

        public async Task<IEnumerable<MKUsedCipher>> GetDefaultUsedCiphers()
        {
            return await getItems<MKUsedCipher>(DEFAULT_USED_CIPHERS);
        }



        public async Task<bool> SaveEncryptionFiles(IEnumerable<MKEncryptionFile> files)
        {
            return await saveItems(FILES_KEY, files);
        }

        public async Task<bool> SaveEncryptionDirs(IEnumerable<MKEncryptionDir> dirs)
        {
            return await saveItems(DIRS_KEY, dirs);
        }

        public async Task<bool> SaveEncryptionTexts(IEnumerable<MKEncryptionText> texts)
        {
            return await saveItems(TEXTS_KEY, texts);
        }

        public async Task<bool> SaveDefaultUsedCiphers(IEnumerable<MKUsedCipher> usedCiphers)
        {
            return await saveItems(DEFAULT_USED_CIPHERS, usedCiphers);
        }

        private static void initDefaultCipher()
        {
            _internalCipher = _internalEncryptor.FindCipherBy("camellia", "bouncy_castle");
        }


        private async Task<IEnumerable<T>> getItems<T>(string key)
        {
            string jsonData = await _rawDataProvider.GetJsonString(key);
            if (string.IsNullOrEmpty(jsonData))
            {
                return new List<T>();
            }

            string decrypted = DecryptWithDefault(jsonData);

            var result = JsonConvert.DeserializeObject<IEnumerable<T>>(decrypted);
            return result ?? new List<T>();
        }

        

        private async Task<bool> saveItems<T>(string key, IEnumerable<T> items)
        {
            string jsonData = items != null && items.Any() ?
                JsonConvert.SerializeObject(items) : 
                string.Empty;

            string encrypted = EncryptWithDefault(jsonData);
            return await _rawDataProvider.SaveJsonString(key, encrypted);
        }



        public static string EncryptWithDefault(string input)
        {
            return _internalEncryptor.Encrypt(input, GLOBAL_APP_PASS, _internalCipher, MKKeySize.Key256);
        }

        public static string DecryptWithDefault(string input)
        {
            return _internalEncryptor.Decrypt(input, GLOBAL_APP_PASS, _internalCipher, MKKeySize.Key256);
        }
    }
}
