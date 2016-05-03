namespace MKEncryptor_Interfaces
{
    public abstract class MKCipherBase
    {
        public abstract string UniqueName { get; }
        public abstract string DisplayName { get; }
        public abstract IMKEncryptionProvider Provider { get; }

        public abstract string Description { get; }
        public abstract string DescriptionLink { get; }

        public virtual MKKeySize[] SupportedKeySizes
        {
            get { return new[] {MKKeySize.Key128, MKKeySize.Key192, MKKeySize.Key256}; }
        }

        public bool IsProviderSet
        {
            get { return Provider != null; }
        }

        public void CheckCipherState()
        {
            if (!IsProviderSet)
            {
                throw new MKException(string.Format("Cipher has not set correct provider ({0})", ToString()));
            }
        }

        protected bool Equals(MKCipherBase other)
        {
            return string.Equals(UniqueName, other.UniqueName) &&
                   Provider != null &&
                   other.Provider != null &&
                   Equals(Provider.UniqueName, other.Provider.UniqueName);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((MKCipherBase) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((UniqueName != null ? UniqueName.GetHashCode() : 0)*397) ^
                       (Provider != null ? Provider.UniqueName.GetHashCode() : 0);
            }
        }


        public override string ToString()
        {
            return string.Format("Cipher: {0} | {1}. Provider: {2}", UniqueName, DisplayName, Provider.DisplayName);
        }
    }
}