package Helper;

import DataObjects.TrustedIssuerData;
import IHV.TrustedListProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.time.chrono.MinguoDate;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class Helper {
    private static long serialNumberBase = System.currentTimeMillis(); // used to make a serial number
    public static HashMap<String, String> ASN1ObjectIdentifiers = new HashMap<>() {{
            put("attestation", "1.3.6.1.4.1.1");
            put("attributes", "1.3.6.1.4.1.2");
        }};
    private static HashMap<String, String[]> attestationTypeAttributeNames = new HashMap<>() {{
        put("CitizenCard", new String[] {"ID", "lastname", "givennames", "dateofbirth", "placeofbirth", "nationality"});
        put("AgeProof", new String[] {"age"});
    }};


    // helpers
    public static Date calculateDate(int hoursInFuture)
    {
        // current time in seconds since epoch (1.1.1970 00:00:00)
        long secs = System.currentTimeMillis() / 1000;


        return new Date((secs + ((long) hoursInFuture * 60 * 60)) * 1000); // how many hours in the future from this point in time
    }
    public static synchronized BigInteger calculateSerialNumber()
    {
        return BigInteger.valueOf(serialNumberBase++);
    }
    public static String GetName(X509Certificate cert) {
        return cert.getSubjectX500Principal().getName().split(",")[0].split("=")[1];
    }

    public static String getAttributeNameFromAttestationTypeAndIndex(String attestationType, int index) {
        return attestationTypeAttributeNames.get(attestationType)[index];
    }



    public static boolean isSelfSigned(X509Certificate cert) {
        return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
    }


    public static PKIXCertPathBuilderResult buildAndVerifyChain(
            X509Certificate cert,
            Set<X509Certificate> additionalCerts) throws GeneralSecurityException {

        if (isSelfSigned(cert)) {
            throw new CertificateException("Leaf certificate cannot be self-signed");
        }

        // Separate roots and intermediates
        Set<X509Certificate> rootCerts = new HashSet<>();
        Set<X509Certificate> intermediateCerts = new HashSet<>();

        for (X509Certificate c : additionalCerts) {
            boolean selfSigned = isSelfSigned(c);
            if (selfSigned) {
                rootCerts.add(c);
            } else {
                intermediateCerts.add(c);
            }
        }

        if (rootCerts.isEmpty()) {
            throw new CertificateException("No root certificates found in additionalCerts");
        }

        // Create TrustAnchor set
        Set<TrustAnchor> trustAnchors = new HashSet<>();

        for (X509Certificate root : rootCerts) {
            trustAnchors.add(new TrustAnchor(root, null));
        }

        Set<X509Certificate> allCertsForStore = new HashSet<>(intermediateCerts);
        allCertsForStore.add(cert);


        CertStore intermediateStore = CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(allCertsForStore)
        );

        // Setup selector for leaf cert
        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(cert);

        // PKIX parameters
        PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(trustAnchors, selector);
        pkixParams.addCertStore(intermediateStore);
        pkixParams.setRevocationEnabled(false);

        // Build path
        CertPathBuilder builder = CertPathBuilder.getInstance("PKIX", "BC");

        return (PKIXCertPathBuilderResult) builder.build(pkixParams);
    }
}
