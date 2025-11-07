package Helper;

import java.util.ArrayList;
import java.util.List;

public class DataRegistry {
    public static List<String> revocationList = new ArrayList<>();

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
        var isRevoked = revocationList.contains(attestationNo);
        if (isRevoked) System.out.println("Proof not valid: revoked - " + attestationNo);
        return isRevoked;
    }

}

