using System.IO;
using Pluralsight.TrustUs.Data;
using Pluralsight.TrustUs.DataStructures;
using Pluralsight.TrustUs.Libraries;

namespace Pluralsight.TrustUs
{
    public class CertificateAuthority
    {
        public void SubmitCertificateRequest(CertificateAuthorityConfiguration certificateAuthorityConfiguration,
            string certificateRequestFileName)
        {
            var certStore = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_ODBC_STORE, certificateAuthorityConfiguration.CertificateStoreOdbcName,crypt.KEYOPT_NONE);

            var requestCertificate = Certificate.ImportCertificateFromFile(certificateFileName);

            crypt.CAAddItem(certStore, requestCertificate);

            crypt.DestroyCert(requestCertificate);
            crypt.KeysetClose(certStore);
        }

        public void IssueCertificate(CertificateAuthorityConfiguration certificateAuthorityConfiguration,
            string certificateEmailAddress, string certificateFileName)
        {
            var caKeyStore = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_FILE, certificateAuthorityConfiguration.SigningKeyFileName, crypt.KEYOPT_READONLY);
            var caKey = crypt.GetPrivateKey(caKeyStore, crypt.KEYID_NAME, certificateAuthorityConfiguration.SigningKeyLabel, certificateAuthorityConfiguration.SigningKeyPassword);
            var certStore = crypt.KeysetOpen(crypt.UNUSED, crypt.KEYSET_ODBC_STORE, certificateAuthorityConfiguration.CertificateStoreOdbcName, crypt.KEYOPT_READONLY);
            var certRequest = crypt.CAGetItem(certStore, crypt.CERTTYPE_REQUEST_CERT, crypt.KEYID_EMAIL, certificateEmailAddress);

            crypt.CACertManagement(crypt.CERTACTION_ISSUE_CERT, certStore, caKey, certRequest);

            var certChain = crypt.CAGetItem(certStore, crypt.CERTTYPE_CERTCHAIN, crypt.KEYID_EMAIL, certificateEmailAddress);

            File.WriteAllText($"{ConfigurationData.BaseDirectory}\\{certificateFileName}", Certificate.ExportCertificateAsText(certChain));

            crypt.DestroyObject(certChain);
            crypt.DestroyObject(certRequest);
            crypt.DestroyObject(caKey);
            crypt.KeysetClose(certStore);
            crypt.KeysetClose(caKeyStore);
        }
    }
}