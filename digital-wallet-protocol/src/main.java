import Helper.CryptoTools;
import Helper.TrustedService;
import Holder.Holder;
import Issuer.Issuer;
import Verifier.Verifier;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

public class main {
    
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        TrustedService.generateIssuers(); // generates 10 fake government bodies "GovernmentBody0" to 9.

        var holder = new Holder();
        var verifier = new Verifier();

        // holder requesting proof from issuer
        holder.requestProof("AgeProof", TrustedService.issuers.get("GovernmentBody0"));

        for (int i = 0; i < 31; i++) {
            System.out.println();
            // holder presenting proof to verifier
            var presentation = holder.presentProof("AgeProof", 2);

            // verification: true / false
            boolean verification = verifier.verify(presentation);
            System.out.println("Holder has a valid proof: " + verification);
            System.out.println("-----------------------------------------");
            System.out.println();
        }

        System.out.println("unique roots: " + Verifier.rootsVerified.size());



    }


}
