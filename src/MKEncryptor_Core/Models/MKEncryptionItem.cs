using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MKEncryptor_Core.Helpers;
using Newtonsoft.Json;

namespace MKEncryptor_Core.Models
{
    public abstract class MKEncryptionItem
    {
        protected MKEncryptionItem(string uniqueName, string displayName, 
            string hash, MKEncryptionState state, DateTime created, DateTime? lastModified, string generatedPassword)
        {
            LastModified = lastModified;
            Created = created;
            UniqueName = uniqueName;
            DisplayName = displayName;
            Hash = hash;
            State = state;
            UsedCiphers = new List<MKUsedCipher>();
            GeneratedPassword = generatedPassword;
        }

        protected MKEncryptionItem()
        {
            
        }

        public string UniqueName { get; private set; }
        public string DisplayName { get; set; }
        public string Hash { get; set; }
        public MKEncryptionState State { get; set; }
        public IList<MKUsedCipher> UsedCiphers { get; set; }

        public DateTime Created { get; private set; }
        public DateTime? LastModified { get; set; }
        public string GeneratedPassword { get; set; }


        [JsonIgnore]
        public bool IsWorking { get; set; }

        [JsonIgnore]
        public string WorkingText { get; set; }

        [JsonIgnore]
        public bool LastExceptionInfoVisible { get; set; }

        [JsonIgnore]
        public string LastExceptionInfo { get; set; }

        [JsonIgnore]
        public byte[] Content { get; set; }

        public override string ToString()
        {
            return DisplayName;
        }

        public void AddUsedCipherAtLastPosition(MKUsedCipher cipher)
        {
            MKValidationHelper.ValidateInputNotEmpty(cipher, "cipher");
            if (UsedCiphers.Any())
            {
                var max = UsedCiphers.Max(x => x.Index);
                cipher.Index = (max + 1);
            }
            else
            {
                cipher.Index = 0;
            }
            UsedCiphers.Add(cipher);
        }

        protected static void Init(MKEncryptionItem item)
        {
            item.UniqueName = Guid.NewGuid().ToString("N");
            item.Created = DateTime.Now;
            item.LastModified = null;
            item.Content = null;
            item.DisplayName = "New item";
            item.State = MKEncryptionState.Decrypted;
            item.UsedCiphers = new List<MKUsedCipher>();
        }

        public void GeneratePasswordIfNull()
        {
            if (string.IsNullOrWhiteSpace(GeneratedPassword))
            {
                var random = new Random(DateTime.Now.Millisecond + Created.Millisecond);
                var stringBuilder = new StringBuilder();
                while (stringBuilder.Length < 4000)
                {
                    if (stringBuilder.Length % 2 == 0)
                        stringBuilder.Append(Guid.NewGuid().ToString("N"));
                    stringBuilder.Append(random.Next(0, 999).ToString());
                }
                GeneratedPassword = stringBuilder.ToString();
            }
        }

    }
}
