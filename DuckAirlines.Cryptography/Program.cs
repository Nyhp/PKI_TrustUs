using System;
using System.IO;

namespace Pluralsight.DuckAirlines.Cryptography
{
    internal class Program
    {
        private const string KeyDirectory = @"C:\Pluralsight\Keys\DuckAir";

        private static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                ShowHelp();
                return;
            }

            switch (args[0])
            {
                case "create":
                    if (!Directory.Exists(KeyDirectory))
                    {
                        Directory.CreateDirectory(KeyDirectory);
                    }
                    var keyConfiguration = Key.ConfigureKeyPair();
                    Key.GenerateKeyPair(keyConfiguration);
                    break;

                case "encrypt":
                    // args[1] = certificate file name
                    // args[2] = plain text file name
                    // args[3] = encrypted data file name
                    var encrypt = Cryptography.Encrypt(
                        args[2],
                        args[1]);
                    File.WriteAllBytes(args[3], encrypt);
                    break;

                case "decrypt":
                    // args[1] = private key file name
                    // args[2] = encrypted data file name
                    // args[3] = plain text file name
                    var plainText = Cryptography.Decrypt(args[2], args[1]);
                    File.WriteAllText(args[3], plainText);
                    break;

                case "sign":
                    // args[1] = private key file name
                    // args[2] = data file name
                    // args[3] = signature file name
                    var dataToBeSigned = File.ReadAllText(args[2]);
                    var generatedSignature = Cryptography.Sign(dataToBeSigned,
                        args[1]);
                    File.WriteAllText(args[3], generatedSignature);
                    break;

                case "verify":
                    // args[1] = certificate file name
                    // args[2] = data file name
                    // args[3] = signature file name
                    var dataToBeVerified = File.ReadAllText(args[2]);
                    var existingSignature = File.ReadAllText(args[3]);
                    var isValid = Cryptography.ValidateSignature(
                        dataToBeVerified, existingSignature,args[1]);
                    if (isValid)
                    {
                        Console.Write("The signature for the data provided is valid");
                    }
                    else
                    {
                        Console.WriteLine("There is a signature and data mismatch.");
                    }
                    break;

                default:
                    ShowHelp();
                    return;
            }
        }

        private static void ShowHelp()
        {
            var helpMessage = "\nDuck Airlines Cryptography (DAC)\n" +
                              "Handles PKI and asymmetric cryptography operations.\n\n" +
                              "Create a new public private key pair\n" +
                              "------------------------------------\n"+
                              " > dac create\n\n" +
                              "Encrypt data\n------------\n" + 
                              " > dac encrypt {certificate file name} {plain text file name} {encrypted file name}\n\n"+
                              "   {certificate file name} is the filename of the public key certificate of the party receiving the data.\n"+
                              "   {plain text file name}  is the filename holding the data to be encrypted.\n"+
                              "   {encrypted file name}   is the filename for the file you want to create to hold the encrypted data."+
                              "Decrypt data\n" +
                              "------------\n" +
                              " > dac decrypt {private key file name} {encrypted data file name} {plain text file name}\n\n" +

                              "   {private key file name} is the filename of the private key of the party receiving the data.\n" +
                              "   {encrypted file name}   is the filename holding the encrypted data.\n" +
                              "   {plain text file name}  is the filename for the file you want to create to hold the decrypted data.\n\n" +

                              "Sign data\n" +
                              "---------\n" +
                              " > dac sign {private key file name} {data file name} {signature file name}\n\n" +

                              "    {private key file name} is the filename that holds the private key of the party signing the data\n" +
                              "    {data file name}        is the filename holding the data to be signed\n" +
                              "    {signature file name}   is the filename for the file that you want to create to hold the signature\n\n" +

                              "Verify data signature\n" +
                              "---------------------\n" +
                              " > dac verify  {certificate file name} {data file name} {signature file name}\n\n" +

                              "    {certificate file name} is the filename that holds the public key of the party that signed the data\n" +
                              "    {data file name}        is the filename holding the data that has been signed\n" +
                              "    {signature file name}   is the filename holding the signature to be validated\n";

            Console.WriteLine(helpMessage);
        }
    }
}
