package Helper;

import IHV.Issuer;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TrustedService {
    // used to emulate a list of issuers
    public static Map<String, Issuer> issuers = new HashMap<>();


    public static List<String> revocationList = new ArrayList<>();

    public static void generateIssuers() {
        for (int i = 0; i < 10; i++) { // random governmentbody
            var name = "GovernmentBody"+i;
            issuers.put(name, new Issuer(name));
        }
    }

    public static PublicKey getPublicKey(String issuer) {
        return issuers.get(issuer).publicKey;
    }

    public static boolean addRevocation(String attestationNo) {
        if (revocationList.contains(attestationNo)) {
            System.out.println("Revocation already exists");
            return false;
        }
        System.out.println("Revocation added - "  + attestationNo);
        revocationList.add(attestationNo);
        return true;
    }

    public static boolean isProofRevoked(String attestationNo) {
        System.out.println("Proof not valid: revoked - " + attestationNo);
        return revocationList.contains(attestationNo);
    }

}
