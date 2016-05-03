using System.Text;
using MKEncryptor_BCProvider;

namespace MKEncryptor_Core.Helpers
{
    public static class MKHashHelper
    {
        public static byte[] GetSHA512(string inputString)
        {
            return BcHashHelper.ComputeSha512(Encoding.UTF8, inputString);
        }

        public static byte[] GetSHA512(byte[] input)
        {
            return BcHashHelper.ComputeSha512(input);
        }

        public static string GetSHA512String(string inputString)
        {
            var sb = new StringBuilder();
            foreach (var b in GetSHA512(inputString))
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }

        public static string GetSHA512String(byte[] input)
        {
            var sb = new StringBuilder();
            foreach (var b in GetSHA512(input))
                sb.Append(b.ToString("X2"));

            return sb.ToString();
        }
    }
}
