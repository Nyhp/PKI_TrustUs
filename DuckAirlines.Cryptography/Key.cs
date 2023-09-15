using System;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Pluralsight.DuckAirlines.Cryptography.DataStructures;

namespace Pluralsight.DuckAirlines.Cryptography
{
    public static class Key
    {
        private const string RootDirectory = @"C:\Pluralsight\Keys\DuckAir";

        public static void GenerateKeyPair(KeyConfiguration keyConfiguration)
        {
            var keyGenerator = new RsaKeyPairGenerator();
            keyGenerator.Init(new KeyGenerationParameters(new SecureRandom(),2048));
            var keyPair = keyGenerator.GenerateKeyPair();

            var signer = new Asn1SignatureFactory("SHA512WITHRSA", keyPair.Private);

            var distinguishedName = new X509Name(
                $"C = {keyConfiguration.DistinguishedName.Country}," + 
                $"ST = {keyConfiguration.DistinguishedName.State}," + 
                $"L = {keyConfiguration.DistinguishedName.Locality}," + 
                $"O = {keyConfiguration.DistinguishedName.Organization}," + 
                $"OU = {keyConfiguration.DistinguishedName.OrganizationalUnit}," + 
                $"CN = {keyConfiguration.DistinguishedName.CommonName}," + 
                $"E = {keyConfiguration.DistinguishedName.EmailAddress},");

            var certificateSigningRequest = new Pkcs10CertificateRequest(
                signer, distinguishedName, keyPair.Public, null);

            var csrTextWriter = new StringWriter();
            var pemCsrWrite = new PemWriter(csrTextWriter);
            pemCsrWrite.WriteObject(certificateSigningRequest);
            pemCsrWrite.Write.Flush();
            File.WriteAllText(RootDirectory + @"\" + keyConfiguration.CertificateRequestFileName, csrTextWriter.ToString());

            var pvkTextWriter = new StringWriter();
            var pemPvkWriter = new PemWriter(pvkTextWriter);
            pemPvkWriter.WriteObject(keyPair.Private);
            pemPvkWriter.Write.Flush();
            File.WriteAllText(RootDirectory + @"\" + keyConfiguration.KeystoreFileName, pvkTextWriter.ToString());

            
        }

        public static KeyConfiguration ConfigureKeyPair()
        {
            var keyConfiguration = new KeyConfiguration();

            Console.WriteLine("\nCertificate Signing Request Certificate\n" +
                              "---------------------------\n" +
                              "This process will create a Public / Private key pair as well as \n" +
                              "create a certificate signing request for the public key.\n" +
                              "You are going to be walked through each piece of information\n" +
                              "needed for the Certificate Signing Request.\n");
            Console.Write("Country: ");
            keyConfiguration.DistinguishedName.Country = Console.ReadLine();
            Console.Write("State or Locality: ");
            keyConfiguration.DistinguishedName.State = Console.ReadLine();
            Console.Write("City: ");
            keyConfiguration.DistinguishedName.Locality = Console.ReadLine();
            Console.Write("Organization: ");
            keyConfiguration.DistinguishedName.Organization = Console.ReadLine();
            Console.Write("Organizational Unit: ");
            keyConfiguration.DistinguishedName.OrganizationalUnit = Console.ReadLine();
            Console.Write("Common Name: ");
            keyConfiguration.DistinguishedName.CommonName = Console.ReadLine();
            Console.Write("Email Address: ");
            keyConfiguration.DistinguishedName.EmailAddress = Console.ReadLine();

            keyConfiguration.KeystoreFileName =
                keyConfiguration.DistinguishedName.CommonName?.Replace(" ", string.Empty) + ".key";
            keyConfiguration.CertificateRequestFileName =
                keyConfiguration.DistinguishedName.CommonName?.Replace(" ", string.Empty) + ".csr";

            Console.Write("Private Key Password: ");
            Console.ReadLine();

            Console.Write($"\nKey Store FileName [{keyConfiguration.KeystoreFileName}]: ");
            var tempFileName = Console.ReadLine();
            if (!string.IsNullOrEmpty(tempFileName)) keyConfiguration.KeystoreFileName = tempFileName;

            Console.Write($"CSR FileName [{keyConfiguration.CertificateRequestFileName}]: ");
            tempFileName = Console.ReadLine();
            if (!string.IsNullOrEmpty(tempFileName)) keyConfiguration.CertificateRequestFileName = tempFileName;

            return keyConfiguration;
        }
    }
}