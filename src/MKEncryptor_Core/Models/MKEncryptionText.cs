using System;

namespace MKEncryptor_Core.Models
{
    public class MKEncryptionText : MKEncryptionItem
    {
        public MKEncryptionText(string uniqueName, string displayName,
            string hash, MKEncryptionState state, DateTime created, DateTime? lastModified, string generatedPassword, string text)
            : base(uniqueName, displayName, hash, state, created, lastModified, generatedPassword)
        {
            Text = text;
        }

        private MKEncryptionText()
        {
            
        }

        public string Text { get; set; }

        public static MKEncryptionText Create()
        {
            var newItem = new MKEncryptionText();
            Init(newItem);
            newItem.DisplayName = "New text";
            newItem.Text = string.Empty;
            return newItem;
        }
    }
}
