using System;
using System.Collections.Generic;
using System.Linq;
using MKEncryptor_Core;
using MKEncryptor_Core.Models;
using MKEncryptor_Interfaces;
using Newtonsoft.Json;
using NUnit.Framework;

namespace MKEncryptor_Core_Tests
{
    [TestFixture]
    public class DataSourceTests
    {

        [Test]
        public async void ShouldGetFilesFromDataSource()
        {
            var dataSource = new MKDataSource(new MKRawDataProviderStatic());
            var files = await dataSource.GetEncryptionFiles();

            Assert.NotNull(files);

            Assert.AreEqual(2, files.Count());
            Assert.AreEqual(2, files.First().UsedCiphers.Count());
            Assert.AreEqual("aes", files.First().UsedCiphers.First().UniqueNameCipher);
            Assert.AreEqual("bouncy_castle", files.First().UsedCiphers.First().UniqueNameProvider);
            Assert.AreEqual(MKEncryptionState.Decrypted, files.Last().State);
        }


        [Test]
        public void ShouldSerializeAndDeserializeFileJson()
        {
            var file = new MKEncryptionFile(
                "file_1",
                "File 1",
                "sklfjeslkjfefsf3f",
                MKEncryptionState.Encrypted,
                DateTime.Now,
                null,
                null,
                @"C:\Encrypted\Files\file.exe",
                "file.exe",
                "exe"
                );
            file.UsedCiphers.Add(new MKUsedCipher(0, "aes", "bouncy_castle", MKKeySize.Key256));
            file.UsedCiphers.Add(new MKUsedCipher(1, "twofish", "bouncy_castle", MKKeySize.Key192));

            var jsonString = JsonConvert.SerializeObject(file);
            var deserialized = JsonConvert.DeserializeObject<MKEncryptionFile>(jsonString);
            
            Assert.False(string.IsNullOrEmpty(jsonString));
            Assert.NotNull(deserialized);

            Assert.AreEqual(2, deserialized.UsedCiphers.Count);
        }



        [Test]
        public void ShouldSerializeAndDeserializeFilesJson()
        {
            var file1 = new MKEncryptionFile(
                "file_1",
                "File 1",
                "sklfjeslkjfefsf3f",
                MKEncryptionState.Encrypted,
                DateTime.Now,
                DateTime.Now,
                null,
                @"C:\Encrypted\Files\file.exe",
                "file",
                "exe"
                );
            file1.UsedCiphers.Add(new MKUsedCipher(0, "aes", "bouncy_castle", MKKeySize.Key256));
            file1.UsedCiphers.Add(new MKUsedCipher(1, "twofish", "bouncy_castle", MKKeySize.Key128));

            var file2 = new MKEncryptionFile(
                "file_2",
                "File 2",
                "sklfjeslkjfsfesfsfsefsefsf3f",
                MKEncryptionState.Decrypted,
                DateTime.Now,
                null,
                null,
                @"C:\Encrypted\Files\file_one.pdb",
                "file_one",
                "pdb"
                );
            file2.UsedCiphers.Add(new MKUsedCipher(0, "serpent", "bouncy_castle", MKKeySize.Key128));
            file2.UsedCiphers.Add(new MKUsedCipher(1, "aes", "bouncy_castle", MKKeySize.Key192));

            var files = new List<MKEncryptionFile>()
            {
                file1,
                file2
            };

            var jsonString = JsonConvert.SerializeObject(files);
            var deserialized = JsonConvert.DeserializeObject<IEnumerable<MKEncryptionFile>>(jsonString);

            Assert.False(string.IsNullOrEmpty(jsonString));
            Assert.NotNull(deserialized);

            Assert.AreEqual(2, deserialized.Count());
            Assert.AreEqual(2, deserialized.First().UsedCiphers.Count());
            Assert.AreEqual(MKEncryptionState.Decrypted, deserialized.Last().State);
        }


        [Test]
        public void ShouldSaveFilesToDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);

            var file1 = new MKEncryptionFile(
                "file_1",
                "File 1",
                "sklfjeslkjfefsf3f",
                MKEncryptionState.Encrypted,
                DateTime.Now,
                DateTime.Now,
                null,
                @"C:\Encrypted\Files\file.exe",
                "file",
                "exe"
                );
            file1.UsedCiphers.Add(new MKUsedCipher(0, "aes", "bouncy_castle", MKKeySize.Key256));
            file1.UsedCiphers.Add(new MKUsedCipher(1, "twofish", "bouncy_castle", MKKeySize.Key128));

            var file2 = new MKEncryptionFile(
                "file_2",
                "File 2",
                "sklfjeslkjfsfesfsfsefsefsf3f",
                MKEncryptionState.Decrypted,
                DateTime.Now,
                null,
                null,
                @"C:\Encrypted\Files\file_one.pdb",
                "file_one",
                "pdb"
                );
            file2.UsedCiphers.Add(new MKUsedCipher(0, "serpent", "bouncy_castle", MKKeySize.Key128));
            file2.UsedCiphers.Add(new MKUsedCipher(1, "aes", "bouncy_castle", MKKeySize.Key192));

            dataSource.SaveEncryptionFiles(new List<MKEncryptionFile>() { file1, file2 });

            Assert.False(string.IsNullOrEmpty(provider.LastSavedJson));
            Assert.NotNull(JsonConvert.DeserializeObject<IEnumerable<MKEncryptionFile>>(provider.LastSavedJson));
        }


        [Test]
        public void ShouldSaveDirsToDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);
            var resultDirs = new List<MKEncryptionDir>();

            for (int i = 0; i < 20; i++)
            {
                var dir1 = new MKEncryptionDir("dir" + i, "Directory " + i, 
                "skjefhskehfksfh", MKEncryptionState.Decrypted,
                DateTime.Now, null, null, @"C:\Encrypted\Files\Dir" + i);
                resultDirs.Add(dir1);
            }
            
            dataSource.SaveEncryptionDirs(resultDirs);

            Assert.False(string.IsNullOrEmpty(provider.LastSavedJson));
            var json = provider.LastSavedJson.Replace('"', '\'');          
            Assert.NotNull(JsonConvert.DeserializeObject<IEnumerable<MKEncryptionDir>>(provider.LastSavedJson));
        }


        [Test]
        public void ShouldSaveTextsToDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);
            var text1 = new MKEncryptionText("text1", "My text 1", "fsesljlfsejfljesf", MKEncryptionState.Decrypted,
                DateTime.Now, null, null, "My looong super text with something special secret");
            var text2 = new MKEncryptionText("text2", "My text 2", "fsefsefsefddd", MKEncryptionState.Decrypted,
                DateTime.Now, null, null, "No way your can read this");
            var text3 = new MKEncryptionText("text3", "My text 3", "sesefsef", MKEncryptionState.Decrypted,
                DateTime.Now, null, null, "Super secret text three");

            dataSource.SaveEncryptionTexts(new List<MKEncryptionText>() { text1, text2, text3 });

            Assert.False(string.IsNullOrEmpty(provider.LastSavedJson));
            Assert.NotNull(JsonConvert.DeserializeObject<IEnumerable<MKEncryptionText>>(provider.LastSavedJson));
        }


        [Test]
        public void ShouldSaveDefaultUsedCiphersToDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);
            var usedCipher = new List<MKUsedCipher>()
            {
                new MKUsedCipher(0, "aes", "bouncy_castle", MKKeySize.Key256),
                new MKUsedCipher(1, "twofish", "bouncy_castle", MKKeySize.Key256)
            };

            dataSource.SaveDefaultUsedCiphers(usedCipher);

            Assert.False(string.IsNullOrEmpty(provider.LastSavedJson));
            Assert.NotNull(JsonConvert.DeserializeObject<IEnumerable<MKUsedCipher>>(provider.LastSavedJson));
        }


        [Test]
        public async void ShouldLoadFilesFromDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);
            var files = await dataSource.GetEncryptionFiles();

            Assert.NotNull(files);
            Assert.AreEqual(2, files.Count());
        }

        [Test]
        public async void ShouldLoadDirsFromDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);
            var dirs = await dataSource.GetEncryptionDirs();

            Assert.NotNull(dirs);
            Assert.AreEqual(20, dirs.Count());
        }

        [Test]
        public async void ShouldLoadTextsFromDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);
            var texts = await dataSource.GetEncryptionTexts();

            Assert.NotNull(texts);
            Assert.AreEqual(3, texts.Count());
        }

        [Test]
        public async void ShouldLoadDefaultUsedCiphersFromDataSource()
        {
            var provider = new MKRawDataProviderStatic();
            var dataSource = new MKDataSource(provider);
            var ciphers = await dataSource.GetDefaultUsedCiphers();

            Assert.NotNull(ciphers);
            Assert.AreEqual(2, ciphers.Count());
        }
    }
}
