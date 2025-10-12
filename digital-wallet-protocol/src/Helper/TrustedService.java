package Helper;

import Issuer.Issuer;

import java.util.HashMap;
import java.util.Map;

public class TrustedService {
    public static Map<String, Issuer> issuers = new HashMap<>();

    public static void generateIssuers() {
        for (int i = 0; i < 10; i++) {
            var name = "GovernmentBody"+i;
            issuers.put(name, new Issuer(name));
        }
    }
}
