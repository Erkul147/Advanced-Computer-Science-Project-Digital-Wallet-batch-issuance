package Helper;

import IHV.Issuer;
import IHV.Registrar;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TrustedService {
    // used to emulate a list of issuers
    public static Map<String, Issuer> issuers = new HashMap<>();
    public static Registrar  registrar = new Registrar();
    public static void generateIssuers() {
        for (int i = 0; i < 2; i++) { // random governmentbody
            var name = "GovernmentBody"+i;
            issuers.put(name, new Issuer(name));
            System.out.println(name);
        }
    }

    public static PublicKey getPublicKey(String issuer) {
        return issuers.get(issuer).publicKey;
    }



}
