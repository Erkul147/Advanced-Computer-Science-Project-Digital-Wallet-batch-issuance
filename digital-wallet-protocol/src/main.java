import DataObjects.VerifiableCredential;
import DataObjects.VerifiablePresentation;
import IHV.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class main {
    
    public static void main(String[] args) {

        // using bouncy castle, and adding it as the provider
        System.out.println("-----------------------------------------");
        System.out.println("Adding the security provider");
        Security.addProvider(new BouncyCastleProvider());

        // creating Registrar and Access Certificate Authority
        System.out.println("-----------------------------------------");
        System.out.println("Creating Registrar and CA");
        TrustedListProvider.registrar = new Registrar();

        // generate new issuers and verifier
        System.out.println("-----------------------------------------");
        System.out.println("Creating Issuers and Verifiers");

        Issuer[] issuers = new Issuer[] {
                new Issuer("GovernmentBody0"),
                new Issuer("GovernmentBody1")
        };

        Verifier[] verifiers = new  Verifier[] {
                new Verifier("Hospital"),
                new Verifier("Kiosk")
        };

        // issuers must specify which attestation they want to create and what info it must hold
        System.out.println("\n-----------------------------------------");
        System.out.println("Issuer0 request Access Certificate to create a Citizen card attestation.");
        issuers[0].requestAccessCertificate("CitizenCard", new String[] {"ID", "lastname", "givennames", "dateofbirth", "placeofbirth", "nationality"});

        // verifier must say which attestation they wish to request data from and what data
        System.out.println("\n-----------------------------------------");
        System.out.println("Verifier0 request Access Certificate to request attributes from a Citizen card attestation.");
        verifiers[0].requestAccessCertificate("CitizenCard", new String[] {"ID", "lastname", "givennames", "dateofbirth"});

        // create holder and request a proof
        System.out.println("\n-----------------------------------------");
        System.out.println("Creating a holder (Wallet).");
        Holder holder = new Holder("DK12345");

        System.out.println("User requesting an attestation (citizen card):");
        holder.requestProof("CitizenCard", issuers[0]);

        // present proof to a verifier
        System.out.println("\n-----------------------------------------");
        System.out.println("User creating a VP to show a verifier");
        VerifiableCredential proof = holder.getProof("CitizenCard");
        VerifiablePresentation VP = holder.presentProof(proof, new int[] {0,2});
        System.out.println(VP.toString());

        System.out.println("\n-----------------------------------------");
        System.out.println("Verifier receives VP and uses it to authenticate the attestation and attributes");
        verifiers[0].verifyMerkleTree(VP);

        System.out.println();



        /*
        System.out.println("Testing inclusion path of merkle trees and signature:");
        testVerificationMerkleTree();
        System.out.println();

       System.out.println("Testing revocation:");
        testRevocation();
        System.out.println();

        System.out.println("Testing authentication steps of hash list:");
        testVerificationHashList();*/

    }


    private static void testVerificationMerkleTree()  {

        var holder = new Holder("DK6789012");
        var verifier = new Verifier("Kiosk");

        // holder requesting proof from issuer
        holder.requestProof("CitizensCard", TrustedListProvider.getTrustedIssuer("GovernmentBody0").issuer());

        for (int i = 0; i < 2; i++) {
            System.out.println();
            // holder presenting proof to verifier

            VerifiableCredential proof = holder.getProof("CitizensCard");
            VerifiablePresentation presentation = holder.presentProof(proof, new int[] {2});

            // verification: true / false
            boolean verification = verifier.verifyMerkleTree(presentation);
            System.out.println("Holder has a valid proof: " + verification);
            System.out.println("-----------------------------------------");
        }

        System.out.println("unique roots: " + Verifier.rootsVerified.size());
        System.out.println("-----------------------------------------\n");

    }

    private static void testRevocation()  {

        System.out.println("creating holder");
        var holder = new Holder("DK6789012");

        System.out.println("creating verifier");
        var verifier = new Verifier("Kiosk");

        System.out.println("request proofs from issuer");
        // holder requesting proof from issuer
        holder.requestProof("CitizensCard", TrustedListProvider.getTrustedIssuer("GovernmentBody0").issuer());


        for (int i = 0; i < 2; i++) {
            System.out.println();
            // holder presenting proof to verifier
            VerifiableCredential proof = holder.getProof("CitizensCard");
            VerifiablePresentation presentation = holder.presentProof(proof, new int[] {2});

            TrustedListProvider.addRevocation(presentation.md().ID());


            // verification: true / false
            boolean verification = verifier.verifyMerkleTree(presentation);
            System.out.println("Holder has a valid proof: " + verification);
            System.out.println("-----------------------------------------");
            System.out.println();
        }

    }


}
