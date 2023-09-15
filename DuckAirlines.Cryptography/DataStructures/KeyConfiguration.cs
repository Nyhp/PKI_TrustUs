namespace Pluralsight.DuckAirlines.Cryptography.DataStructures
{
    public class KeyConfiguration
    {
        public KeyConfiguration()
        {
            DistinguishedName = new DistinguishedName();
        }

        /// <summary>
        /// Gets or sets the name of the keystore file.
        /// </summary>
        /// <value>The name of the keystore file.</value>
        public string KeystoreFileName { get; set; }

        /// <summary>
        /// Gets or sets the name of the certificate file.
        /// </summary>
        /// <value>The name of the certificate file.</value>
        public string CertificateRequestFileName { get; set; }
        
        /// <summary>
        /// Gets or sets the name of the distinguished.
        /// </summary>
        /// <value>The name of the distinguished.</value>
        public DistinguishedName DistinguishedName { get; }

    }
}