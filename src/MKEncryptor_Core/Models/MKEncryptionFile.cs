using System;

namespace MKEncryptor_Core.Models
{
    public class MKEncryptionFile : MKEncryptionItem
    {
        public MKEncryptionFile(string uniqueName, string displayName, 
            string hash, MKEncryptionState state, DateTime created, DateTime? lastModified, string generatedPassword,
            string path, string originalName, string originalExtension) 
            : base(uniqueName, displayName, hash, state, created, lastModified, generatedPassword)
        {
            OriginalExtension = originalExtension;
            OriginalName = originalName;
            Path = path;
        }

        private MKEncryptionFile()
        {
            
        }

        public string Path { get; set; }
        public string OriginalName { get; private set; }
        public string OriginalExtension { get; private set; }

        public static MKEncryptionFile Create()
        {
            var newItem = new MKEncryptionFile();
            Init(newItem);
            newItem.DisplayName = "New file";
            newItem.Path = string.Empty;
            newItem.OriginalName = string.Empty;
            newItem.OriginalExtension = string.Empty;
            return newItem;
        }
    }
}
