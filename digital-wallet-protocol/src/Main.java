import CommitmentSchemes.HashList;
import Helper.TrustedService;
import DataObjects.VerifiablePresentation;
import IHV.Holder;
import IHV.Verifier;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Main {
    
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        //testRevocation();
        HashList hashList = new HashList(new String[]{"a", "b", "c", "d"});




    }

    private static void testRevocation() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        TrustedService.generateIssuers(); // generates 10 fake government bodies "GovernmentBody0" to 9.

        var holder = new Holder();
        var verifier = new Verifier();

        // holder requesting proof from issuer
        holder.requestProof("CitizensCard", TrustedService.issuers.get("GovernmentBody0"));

        for (int i = 0; i < 2; i++) {
            System.out.println();
            // holder presenting proof to verifier
            VerifiablePresentation presentation = holder.presentProof("CitizensCard", 2);

            TrustedService.addRevocation(presentation.md.ID);


            // verification: true / false
            boolean verification = verifier.verify(presentation);
            System.out.println("Holder has a valid proof: " + verification);
            System.out.println("-----------------------------------------");
            System.out.println();
        }

        System.out.println("unique roots: " + Verifier.rootsVerified.size());
    }





}
