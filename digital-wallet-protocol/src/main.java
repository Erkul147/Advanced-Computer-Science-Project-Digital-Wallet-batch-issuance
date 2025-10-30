import CommitmentSchemes.HashList;
import CommitmentSchemes.MerkleTree;
import DataObjects.AuthenticationSteps;
import Helper.CryptoTools;
import Helper.TrustedService;
import DataObjects.VerifiablePresentation;
import IHV.DataRegistry;
import IHV.Holder;
import IHV.Verifier;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class main {
    
    public static void main(String[] args) {
        // Execution time for merkle tree
        int n = 10000;
        ArrayList<String> attributes = new ArrayList<>();

        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForMerkleTree.csv"))) {
            bw.write("type,amountOfAttributes,executionTime");
            bw.newLine();
            for (int i = 1; i < n; i++) {

                attributes.add(Integer.toString(i));

                Timestamp before = new Timestamp(System.currentTimeMillis());
                new MerkleTree(attributes.toArray(new String[0]));
                Timestamp after = new Timestamp(System.currentTimeMillis());
                var executionTime = after.getTime() - before.getTime();
                bw.write("merkletree," + i + "," + executionTime);
                bw.newLine();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }

        // Execution time for hashlist
        /*
        int n = 10000;
        ArrayList<String> attributes = new ArrayList<>();

        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForHashList.csv"))) {
            bw.write("type,amountOfAttributes,executionTime");
            bw.newLine();
            for (int i = 1; i < n; i++) {

                attributes.add(Integer.toString(i));

                Timestamp before = new Timestamp(System.currentTimeMillis());
                new HashList(attributes.toArray(new String[0]));
                Timestamp after = new Timestamp(System.currentTimeMillis());
                var executionTime = after.getTime() - before.getTime();
                bw.write("hashlist," + i + "," + executionTime);
                bw.newLine();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        */


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
        var verifier = new Verifier();

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
        var verifier = new Verifier();

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
