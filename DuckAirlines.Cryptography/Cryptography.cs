using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Pluralsight.DuckAirlines.Cryptography
{
    public static class Cryptography
    {
        public static byte[] Encrypt(string plainTextDataFileName, string certificateFileName)
        {
            var bytesToEncrypt = Encoding.UTF8.GetBytes(plainTextDataFileName);
            var encryptionEngine = new Pkcs1Encoding(new RsaEngine());

            var parser = new X509CertificateParser();
            var certificateFileStream = new FileStream(certificateFileName, FileMode.Open);
            var certificate = parser.ReadCertificate(certificateFileStream);
            encryptionEngine.Init(true, certificate.GetPublicKey());
            var processBlock = encryptionEngine.processBlock(bytesToEncrypt, 0, bytesToEncrypt.Length);
            
            return processBlock;
        }

        public static string Decrypt(string encryptedDataFileName, string privateKeyFileName)
        {
            var decryptionEngine = new Pkcs1Encoding(new RsaEngine());

            var rawKeyFromFile = File.ReadAllText(privateKeyFileName);
            var rawKey = new StringReader(rawKeyFromFile);
            var pemReader = new PemReader(rawKey);
            var pemObject = (AsymmetricCipherKeyPair)pemReader.ReadObject();

            decryptionEngine.Init(false, pemObject.Private);
            var decryptedByteData = decryptionEngine.processBlock(encryptedDataFileName, 0, encryptedDataFileName.Length);
            var plainTextData = Encoding.UTF8.GetString(decryptedByteData);

            return plainTextData;
        }

        public static string Sign(string data, string privateKeyFileName)
        {
            var dataAsBytes = Encoding.UTF8.GetBytes(data);

            var rawKeyFromFile = File.ReadAllText(privateKeyFileName);
            var rawKey = new StringReader(rawKeyFromFile);
            var pemReader = new PemReader(rawKey);
            var pemObject = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            var signer = SignerUtilities.InitSigner("SHA1withRSA", true, pemObject.Private, new SecureRandom());
            signer.BlockUpdate(dataAsBytes, 0, dataAsBytes.Length);
            var signature = signer.GenerateSignature();

            var encodedSignature = Convert.ToBase64String(signature);

            return encodedSignature;
        }

        public static bool ValidateSignature(string data, string encodedSignature, string certificateFileName)
        {
            var parser = new X509CertificateParser();
            var certificate = parser.ReadCertificate(new FileStream(certificateFileName, FileMode.Open));
            var validator = SignerUtilities.InitSigner("SHA1withRSA", false, certificate.GetPublicKey(), new SecureRandom());

            var dataAsBytes = Encoding.UTF8.GetBytes(data);
            validator.BlockUpdate(dataAsBytes, 0, dataAsBytes.Length);

            var signature = Convert.FromBase64String(encodedSignature);
            var isValid = validator.VerifySignature(signature);

            return isValid;
        }
    }
}
