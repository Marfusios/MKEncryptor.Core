using System;

namespace MKEncryptor_Core.Models
{
    public class MKEncryptionDir : MKEncryptionItem
    {
        public MKEncryptionDir(string uniqueName, string displayName,
            string hash, MKEncryptionState state, DateTime created, DateTime? lastModified, string generatedPassword, string path)
            : base(uniqueName, displayName, hash, state, created, lastModified, generatedPassword)
        {
            Path = path;
        }

        private MKEncryptionDir()
        {         
        }

        public string Path { get; set; }

        public static MKEncryptionDir Create()
        {
            var newItem = new MKEncryptionDir();
            Init(newItem);
            newItem.DisplayName = "New directory";
            newItem.Path = string.Empty;
            return newItem;
        }
    }
}
