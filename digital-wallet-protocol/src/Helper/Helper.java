package Helper;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.chrono.MinguoDate;
import java.util.Date;
import java.util.HashMap;

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
}
