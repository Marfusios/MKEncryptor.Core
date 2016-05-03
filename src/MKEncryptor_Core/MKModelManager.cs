using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using MKEncryptor_Core.Models;

namespace MKEncryptor_Core
{
    public class MKModelManager
    {
        private readonly MKDataSource _dataSource;

        public MKModelManager(IMKRawDataProvider rawDataProvider)
        {
            _dataSource = new MKDataSource(rawDataProvider);
            init();
        }

        public ObservableCollection<MKEncryptionFile> Files { get; private set; }
        public ObservableCollection<MKEncryptionDir> Dirs { get; private set; }
        public ObservableCollection<MKEncryptionText> Texts { get; private set; }

        public ObservableCollection<MKUsedCipher> DefaultUsedCiphers { get; private set; }

        public List<MKEncryptionItem> Items
        {
            get 
            { 
                return Files
                    .Cast<MKEncryptionItem>()
                    .Concat(Dirs)
                    .Concat(Texts)
                    .ToList(); 
            }
        }

        public async Task<bool> SaveChanges()
        {
            await _dataSource.SaveEncryptionFiles(Files);
            await _dataSource.SaveEncryptionDirs(Dirs);
            await _dataSource.SaveEncryptionTexts(Texts);
            await _dataSource.SaveDefaultUsedCiphers(DefaultUsedCiphers);
            return true;
        }

        public async Task<bool> Reload()
        {
            Clear();

            addAllTo((await _dataSource.GetEncryptionFiles()).ToList(), Files);
            addAllTo((await _dataSource.GetEncryptionDirs()).ToList(), Dirs);
            addAllTo((await _dataSource.GetEncryptionTexts()).ToList(), Texts);
            addAllTo((await _dataSource.GetDefaultUsedCiphers()).ToList(), DefaultUsedCiphers);

            return true;
        }

        public void Clear()
        {
            Files.Clear();
            Dirs.Clear();
            Texts.Clear();
            DefaultUsedCiphers.Clear();
        }


        public void Remove(MKEncryptionItem item)
        {
            var file = item as MKEncryptionFile;
            var dir = item as MKEncryptionDir;
            var text = item as MKEncryptionText;

            if (file != null) Files.Remove(file);
            if (dir != null) Dirs.Remove(dir);
            if (text != null) Texts.Remove(text);
        }
 

        private void init()
        {
            Files = new ObservableCollection<MKEncryptionFile>();
            Dirs = new ObservableCollection<MKEncryptionDir>();
            Texts = new ObservableCollection<MKEncryptionText>();
            DefaultUsedCiphers = new ObservableCollection<MKUsedCipher>();
        }

        private void addAllTo<T>(List<T> from, ObservableCollection<T> to)
        {
            foreach (var item in from)
            {
                to.Add(item);
            }
        }
    }
}
