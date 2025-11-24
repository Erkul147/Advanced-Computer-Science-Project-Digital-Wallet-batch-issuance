import CommitmentSchemes.HashList;
import CommitmentSchemes.MerkleTree;
import DataObjects.AuthenticationSteps;
import DataObjects.DisclosedAttribute;
import DataObjects.InclusionPath;
import Helper.CryptoTools;
import Helper.TrustedService;
import DataObjects.VerifiablePresentation;
import IHV.DataRegistry;
import IHV.Holder;
import IHV.Verifier;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.*;

public class main {
    
    public static void main(String[] args) {


        ArrayList<Integer> integers = new ArrayList<>();
        for (int j = 1; j <= 100; j++) {
            integers.add(j);
        }


        var now = System.currentTimeMillis();
        while (now + 20000 >  System.currentTimeMillis()) {
            // do nothing, warm up.
        }

        int[] amountOfAttributes = new int[] {50,100,150,200,250,300};

        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForMerkleTreeGeneratePath.csv"))) {
            bw.write("type,amountOfAttributes,runNo,executionTime");
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                int amountOfAttribute = amountOfAttributes[i];
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttribute, "attribute"));
                var merkleTree = new MerkleTree(attributes.toArray(new String[0]));

                // Execution time for merkletree
                for (int j = 0; j < 10000; j++) {
                    bw.newLine();
                    long before = System.nanoTime();
                    var pathMerkleTree = merkleTree.generateInclusionPath(amountOfAttribute-1);
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("merkletree," + amountOfAttribute + "," + (j + 1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForHashListGeneratePath.csv"))) {
            bw.write("type,amountOfAttributes,runNo,executionTime");
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                int amountOfAttribute = amountOfAttributes[i];
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttribute, "attribute"));
                var hashList = new HashList(attributes.toArray(new String[0]));
                // Execution time for hashlist
                bw.newLine();
                for (int j = 0; j < 10000; j++) {
                    long before = System.nanoTime();
                    var pathHashList = hashList.generateAuthenticationPath(integers);
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("hashlist," + amountOfAttribute + "," + (j + 1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void HashListVSMerkleTreeGeneration() {
        // Execution time for merkle tree
        int[] amountOfAttributes = new int[] {50,100,150,200,250,300};
        int n = 10000;

        long now = System.currentTimeMillis();
        while (now + 20000 >  System.currentTimeMillis()) {
            // do nothing, warm up.
        }
        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForMerkleTree.csv"))) {
            bw.write("type,amountOfAttributes,runNo,executionTime");
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttributes[i], "attribute"));
                bw.newLine();
                for (int j = 0; j < n; j++) {
                    long before = System.nanoTime();
                    new MerkleTree(attributes.toArray(new String[0]));
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("merkletree," + amountOfAttributes[i] + "," + (j+1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForHashList.csv"))) {
            bw.write("type,amountOfAttributes,runNo,executionTime");
            // Execution time for hashlist
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttributes[i], "attribute"));
                bw.newLine();
                for (int j = 0; j < n; j++) {
                    long before = System.nanoTime();
                    new HashList(attributes.toArray(new String[0]));
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("hashlist," + amountOfAttributes[i] + "," + (j+1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean verifyHashList(AuthenticationSteps authenticationPath, byte[][] hashes, byte[] expectedHash) {
        var combinedHashes = new byte[0];

        for (int i = 0; i < hashes.length; i++) {
            // if the index of the list is a disclosed attribute, concat attribute and salt, then hash it

            if (authenticationPath.indexes.contains(i)) {
                int listIndex = authenticationPath.indexes.get(i);
                String attribute = authenticationPath.attributes.get(i);
                byte[] salt = authenticationPath.salts.get(i);

                var combineAttributeAndSalt = CryptoTools.combineByteArrays(attribute.getBytes(), salt);
                var hash = CryptoTools.hashSHA256(combineAttributeAndSalt);
                hashes[listIndex] = hash;
            } else System.out.println("Attribute not disclosed");

            combinedHashes =  CryptoTools.combineByteArrays(combinedHashes, hashes[i]);

        }

        var finalHash =  CryptoTools.hashSHA256(combinedHashes);

        return finalHash ==  expectedHash;

    }


    public static boolean verifyMerkleTree(InclusionPath path, DisclosedAttribute disclosedAttribute, byte[] expectedHash) {

        // hashing disclosed attribute with salt
        var combinedAttributes = CryptoTools.combineByteArrays(disclosedAttribute.value, disclosedAttribute.salt);
        var hash = CryptoTools.hashSHA256(combinedAttributes);

        // will loop over the list of hashes. each loop will compute a new hash that is used to compute the next node
        for (int i = 0; i < path.hashes.size(); i++) {
            // if sibling is left then H(sibling, current node) else H(current node, sibling)
            hash = (path.isSiblingLeft.get(i)) ?
                    CryptoTools.hashSHA256(CryptoTools.combineByteArrays(path.hashes.get(i), hash)) :
                    CryptoTools.hashSHA256(CryptoTools.combineByteArrays(hash, path.hashes.get(i)));
        }

        return hash ==  expectedHash;
    }








}
