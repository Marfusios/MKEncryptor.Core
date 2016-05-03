using System.Threading.Tasks;

namespace MKEncryptor_Core
{
    public interface IMKRawDataProvider
    {
        Task<string> GetJsonString(string key);
        Task<bool> SaveJsonString(string key, string json);
    }
}
