package IHV;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class TrustedService {
    // used to emulate a list of issuers
    public static Map<String, Issuer> issuers = new HashMap<>();
    public static Registrar  registrar;
    public static AccessCertificateAuthority ACA;

    public static Issuer[] generateIssuers() {
        for (int i = 0; i < 2; i++) { // random governmentbody
            var name = "GovernmentBody"+i;
            issuers.put(name, new Issuer(name));
            System.out.println(name);
        }

        return issuers.values().toArray(new Issuer[0]);
    }

    public static PublicKey getPublicKey(String issuer) {
        return issuers.get(issuer).publicKey;
    }



}
