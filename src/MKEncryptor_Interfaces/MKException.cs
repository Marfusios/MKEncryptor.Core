using System;

namespace MKEncryptor_Interfaces
{
    public class MKException : Exception
    {
        public MKException()
        {

        }

        public MKException(string msg)
            : base(msg)
        {

        }

        public MKException(string msg, Exception inner)
            : base(msg, inner)
        {
        }
        
    }
}
