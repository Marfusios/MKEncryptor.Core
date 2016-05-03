using System.Collections.Generic;
using System.Collections.ObjectModel;
using MKEncryptor_Interfaces;

namespace MKEncryptor_Core.Helpers
{
    public static class MKEnumerableHelper
    {


        public static void AddRange<T>(this ObservableCollection<T> collection, IEnumerable<T> items)
        {
            if(collection == null || items == null)
                return;

            foreach (var item in items)
            {
                collection.Add(item);
            }
        }



        public static string ArrayToString<T>(T[] array)
        {
            var result = string.Empty;
            foreach (var item in array)
            {
                result += item + ", ";
            }
            return result;
        }

        public static string ArrayToString(MKKeySize[] array)
        {
            var result = string.Empty;
            foreach (var item in array)
            {
                result += (int)item + ", ";
            }
            return result.TrimEnd(' ', ',');
        }

    }
}
