import CommitmentSchemes.HashList;
import DataObjects.AuthenticationSteps;
import Helper.CryptoTools;
import Helper.DataRegistry;
import DataObjects.VerifiablePresentation;
import IHV.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.Arrays;

public class main {
    
    public static void main(String[] args) {

        // using bouncy castle, and adding it as the provider
        Security.addProvider(new BouncyCastleProvider());

        // creating Registrar and Access Certificate Authority
        TrustedListProvider.registrar = new Registrar();

        // generate new issuers and verifier
        Issuer[] issuers = new Issuer[] {
                new Issuer("GovernmentBody0"),
                new Issuer("GovernmentBody1")
        };
        Verifier[] verifiers = new  Verifier[] {
                new Verifier("Kiosk"),
                new Verifier("Hospital")
        };

        // issuers must specify which attestation they want to create and what info it must hold
        issuers[0].requestAccessCertificate("CitizenCard", new String[] {"ID", "Full Name", "DOB", "Address", "Resident Country"});
        issuers[1].requestAccessCertificate("AgeProof", new String[] {"DOB"});

        // verifier must say which attestation they wish to request data from and what data
        verifiers[0].requestAccessCertificate("AgeProof", new String[] {"DOB"});
        verifiers[1].requestAccessCertificate("Citizen Card", new String[] {"ID", "Full Name", "DOB"});


        // create holder and request a proof
        Holder holder = new Holder("DK12345");
        holder.requestProof("AgeProof", issuers[1]);

        // present proof to a verifier
        var VP = holder.presentProof("AgeProof", 0);

        verifiers[1].verifyMerkleTree(VP);

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


    private static void testVerificationHashList() {
        HashList hashList = new HashList(new String[]{"a", "b", "c", "d"});
        var disclosedAttributeIndexes = new int[] {1,2,0};
        var authenticationPath = hashList.generateAuthenticationPath(disclosedAttributeIndexes);
        verifyHashList(authenticationPath, hashList.list);
    }

    private static void verifyHashList(AuthenticationSteps authenticationPath, byte[][] hashes) {

        System.out.println("testing verification");
        int counter = 0;
        var combinedHashes = new byte[0];

        for (int i = 0; i < hashes.length; i++) {
            // if the index of the list is a disclosed attribute, concat attribute and salt, then hash it
            System.out.println("working on index: " + i);

            if (authenticationPath.indexes.contains(i)) {
                int listIndex = authenticationPath.indexes.get(counter);
                String attribute = authenticationPath.attributes.get(counter);
                byte[] salt = authenticationPath.salts.get(counter);
                System.out.println("disclosed attribute: " + attribute);

                counter++;
                var combineAttributeAndSalt = CryptoTools.combineByteArrays(attribute.getBytes(), salt);
                var hash = CryptoTools.hashSHA256(combineAttributeAndSalt);
                hashes[listIndex] = hash;
            } else System.out.println("Attribute not disclosed");

            combinedHashes =  CryptoTools.combineByteArrays(combinedHashes, hashes[i]);

        }

        var finalHash =  CryptoTools.hashSHA256(combinedHashes);

        System.out.println("Combined hashes: " + Arrays.toString(combinedHashes));
        System.out.println("final hash: " + Arrays.toString(finalHash));


    }
    private static void testVerificationMerkleTree()  {

        var holder = new Holder("DK6789012");
        var verifier = new Verifier("Kiosk");

        // holder requesting proof from issuer
        holder.requestProof("CitizensCard", TrustedService.issuers.get("GovernmentBody0"));

        for (int i = 0; i < 2; i++) {
            System.out.println();
            // holder presenting proof to verifier
            VerifiablePresentation presentation = holder.presentProof("CitizensCard", 2);

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
        holder.requestProof("CitizensCard", TrustedService.issuers.get("GovernmentBody0"));


        for (int i = 0; i < 2; i++) {
            System.out.println();
            // holder presenting proof to verifier
            VerifiablePresentation presentation = holder.presentProof("CitizensCard", 2);

            DataRegistry.addRevocation(presentation.md.ID);


            // verification: true / false
            boolean verification = verifier.verifyMerkleTree(presentation);
            System.out.println("Holder has a valid proof: " + verification);
            System.out.println("-----------------------------------------");
            System.out.println();
        }

    }







}
