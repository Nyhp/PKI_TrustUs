using Pluralsight.TrustUs.DataStructures;
using Pluralsight.TrustUs.Libraries;

namespace Pluralsight.TrustUs
{
    public static class Key
    {
        public static byte[] GetPrivateKey(string fileName, string keyLabel, string password)
        {
            var privateKeySize = 4096;
            var keyStore = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, fileName, crypt.KEYOPT_READONLY);
            var privateKeyId = crypt.GetPrivateKey(keyStore, crypt.KEYID_NAME, keyLabel, password);
            var keyContext = crypt.CreateContext(crypt.UNUSED, crypt.ALGO_RSA);
            var privateKey = new byte[privateKeySize];
            crypt.ExportKeyEx(privateKey, privateKeySize, crypt.FORMAT_SMIME, privateKeyId, keyContext);
            crypt.DestroyContext(keyContext);
            crypt.KeysetClose(keyStore);
            return privateKey;
        }

        public static int GetPrivateKeyHandle(string fileName, string keyLabel, string password)
        {
            var keyStore = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, fileName, crypt.KEYOPT_READONLY);
            var privateKeyId = crypt.GetPrivateKey(keyStore, crypt.KEYID_NAME, keyLabel, password);
            crypt.KeysetClose(keyStore);
            return privateKeyId;
        }

        public static int GenerateKeyPair(KeyConfiguration keyConfiguration)
        {
           var keyContext = crypt.CreateContext(crypt.UNUSED, crypt.ALGO_RSA);
           crypt.SetAttributeString(keyContext, crypt.CTXINFO_LABEL, keyConfiguration.keyLabel);
           crypt.SetAttribute(keyContext, crypt.CTXINFO_KEYSIZE, 2048/8);
           crypt.GenerateKey(keyContext);

           var keyStore = 0;

           try
           {
            keyStore = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, keyConfiguration.KeystoreFileName, crypt.KEYOPT_NONE);
           }
           catch(CryptException cryptExeption)
           {
            if(cryptExeption.Status != crypt.ERROR_NOTFOUND)
            {
                throw;
            }

            keyStore = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, keyConfiguration.KeystoreFileName, crypt.KEYOPT_CREATE);)
           }

           crypt.AddPrivateKey(keyStore, keyContext, keyConfiguration.PrivateKeyPassword);
           crypt.KeysetClose(keyStore);
           return keyContext;
        }
    }
}