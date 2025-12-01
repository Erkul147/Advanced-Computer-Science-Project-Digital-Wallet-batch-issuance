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



        int[] amountOfAttributes = new int[] {50,100,150,200,250,300};

        int n = 10000;

        var now = System.currentTimeMillis();
        while (now + 20000 >  System.currentTimeMillis()) {
            new HashList(new String[] {"attribute"});
            new MerkleTree(new String[] {"attribute"});
        }



        System.out.println("Testing generation of merkle");
        merkeTreeGeneration(amountOfAttributes, n);
        System.out.println("Testing generation of hash lists");
        hashListGeneration(amountOfAttributes, n);
        System.out.println("Testing generation of Merkle proof");
        merkleTreeGenerateProof(amountOfAttributes);
        System.out.println("Testing generation of hashlist auth");
        hashListAuthenticationPath(amountOfAttributes);
        System.out.println("testing Verification of merkle proof");
        merkleProofVerification(amountOfAttributes);
        System.out.println("testing Verification of hashlist");
        hashListVerification(amountOfAttributes);
    }

    public static long benchmark(Runnable task, int warmup, int iterations) {
        // Warm-up phase (JIT optimization happens here)
        for (int i = 0; i < warmup; i++) {
            task.run();
        }

        // Actual timed benchmark
        long totalTime = 0;
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            task.run();
            long end = System.nanoTime();
            totalTime += (end - start);
        }

        return totalTime / iterations;  // return average time
    }

    private static void hashListAuthenticationPath(int[] amountOfAttributes) {
        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForHashListGeneratePath.csv"))) {
            bw.write("type,testType,amountOfAttributes,runNo,executionTime");
            bw.newLine();
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                int amountOfAttribute = amountOfAttributes[i];
                ArrayList<Integer> integers = new ArrayList<>();
                for (int j = 0; j < amountOfAttribute; j++) {
                    integers.add(Integer.valueOf(j));
                }
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttribute, "attribute"));
                var hashList = new HashList(attributes.toArray(new String[0]));

                // Execution time for hashlist
                for (int j = 0; j < 10000; j++) {
                    long before = System.nanoTime();
                    var pathHashList = hashList.generateAuthenticationPath(integers);
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("hashlist,authPath," + amountOfAttribute + "," + (j + 1) + "," + executionTime);
                    bw.newLine();
                }

            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void merkleTreeGenerateProof(int[] amountOfAttributes) {
        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForMerkleTreeGeneratePath.csv"))) {
            bw.write("type,testType,amountOfAttributes,runNo,executionTime");
            bw.newLine();
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                int amountOfAttribute = amountOfAttributes[i];

                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttribute, "attribute"));
                var merkleTree = new MerkleTree(attributes.toArray(new String[0]));

                // Execution time for merkletree
                for (int j = 0; j < 10000; j++) {
                    long before = System.nanoTime();
                    for (int k = 0; k < amountOfAttribute; k++) {
                        var pathMerkleTree = merkleTree.generateInclusionPath(k);
                    }
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("merkletree,authPath," + amountOfAttribute + "," + (j + 1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void hashListGeneration(int[] amountOfAttributes, int n) {
        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForHashListGen.csv"))) {
            bw.write("type,testType,amountOfAttributes,runNo,executionTime");
            // Execution time for hashlist
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttributes[i], "attribute"));
                bw.newLine();
                for (int j = 0; j < n; j++) {
                    long before = System.nanoTime();
                    var hs = new HashList(attributes.toArray(new String[0]));
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("hashlist,generation," + amountOfAttributes[i] + "," + (j+1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void merkeTreeGeneration(int[] amountOfAttributes, int n) {
        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForMerkleTreeGen.csv"))) {
            bw.write("type,testType,amountOfAttributes,runNo,executionTime");
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttributes[i], "attribute"));
                bw.newLine();
                for (int j = 0; j < n; j++) {
                    long before = System.nanoTime();
                    var mrkleTree = new MerkleTree(attributes.toArray(new String[0]));
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("merkletree,generation," + amountOfAttributes[i] + "," + (j+1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void merkleProofVerification(int[] amountOfAttributes) {

        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForMerkleTreeVerification.csv"))) {
            bw.write("type,testType,amountOfAttributes,runNo,executionTime");
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                int amountOfAttribute = amountOfAttributes[i];
                ArrayList<Integer> integers = new ArrayList<>();
                for (int j = 0; j < amountOfAttribute; j++) {
                    integers.add(Integer.valueOf(j));
                }
                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttribute, "attribute"));
                var mrkleTree = new MerkleTree(attributes.toArray(new String[0]));
                InclusionPath[] paths = new  InclusionPath[integers.get(i)];
                DisclosedAttribute[] disclosedAttributes = new  DisclosedAttribute[integers.get(i)];

                for (int j = 0; j < integers.get(i); j++) {
                    InclusionPath pathMerkle = mrkleTree.generateInclusionPath(j);
                    paths[j]  = pathMerkle;

                    DisclosedAttribute disclosedAttribute = new DisclosedAttribute(mrkleTree.salts[j], mrkleTree.attributes[j].getBytes());
                    disclosedAttributes[j] = disclosedAttribute;
                }

                bw.newLine();
                for (int j = 0; j < 10000; j++) {
                    long before = System.nanoTime();
                    for (int k = 0; k < disclosedAttributes.length; k++) {
                        if (!verifyMerkleTree(paths[k], disclosedAttributes[k], mrkleTree.root.hash)) throw new RuntimeException();
                    }
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("merkletree,verification," + amountOfAttribute + "," + (j + 1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void hashListVerification(int[] amountOfAttributes) {
        System.gc();
        try (BufferedWriter bw = new BufferedWriter(new FileWriter("timeExecutionForHashListVerification.csv"))) {
            bw.write("type,testType,amountOfAttributes,runNo,executionTime");
            for (int i = 0; i < amountOfAttributes.length-1; i++) {
                int amountOfAttribute = amountOfAttributes[i];
                ArrayList<Integer> integers = new ArrayList<>();
                for (int j = 0; j < amountOfAttribute; j++) {
                    integers.add(Integer.valueOf(j));
                }

                ArrayList<String> attributes = new ArrayList<>(Collections.nCopies(amountOfAttribute, "attribute"));
                var hashList = new HashList(attributes.toArray(new String[0]));
                var pathHashList = hashList.generateAuthenticationPath(integers);

                // Execution time for hashlist
                bw.newLine();
                for (int j = 0; j < 10000; j++) {
                    long before = System.nanoTime();
                    if (!verifyHashList(pathHashList, hashList.list, hashList.finalHash))  throw new RuntimeException();
                    long after = System.nanoTime();
                    var executionTime = after - before;
                    bw.write("hashlist,verification," + amountOfAttribute + "," + (j + 1) + "," + executionTime);
                    bw.newLine();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean verifyHashList(AuthenticationSteps authenticationPath, byte[][] hashes, byte[] expectedHash) {

        for (int i = 0; i < hashes.length; i++) {

            if (authenticationPath.indexes.contains(i)) {
                int listIndex = authenticationPath.indexes.get(i);
                String attribute = authenticationPath.attributes.get(i);
                byte[] salt = authenticationPath.salts.get(i);

                var combineAttributeAndSalt = CryptoTools.combineByteArrays(attribute.getBytes(), salt);
                var hash = CryptoTools.hashSHA256(combineAttributeAndSalt);
                hashes[listIndex] = hash;
            }


        }

        var finalHash = CryptoTools.hashSHA256List(hashes);
        return Arrays.equals(finalHash, expectedHash);
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

        return Arrays.equals(hash, expectedHash);
    }

}
