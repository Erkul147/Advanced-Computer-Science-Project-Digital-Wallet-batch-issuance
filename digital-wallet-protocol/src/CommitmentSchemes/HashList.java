package CommitmentSchemes;

import Helper.CryptoTools;

import java.util.Arrays;

public class HashList {
    public byte[][] salts;
    public String[] attributes;
    public byte[][] list;
    public byte[] finalHash;

    public HashList(String[] attributes) {
        this.attributes = attributes;
        salts = new byte[attributes.length][20];
        createHashList();
    }

    private void createHashList () {
        byte[] combinedHashes = new byte[0];
        list = new byte[attributes.length][32]; // SHA-256 bit: 256 bit / 8 = 32 byte.
        System.out.println("Is combinedHashes empty?: " + Arrays.toString(combinedHashes));
        for (int i = 0; i < attributes.length; i++) {
            // generate a new salt for each leaf node
            salts[i] = CryptoTools.generateSalt(20);

            // combine the attribute with the salt and has them together
            var combinedAttributeSalt = CryptoTools.combineByteArrays(attributes[i].getBytes(), salts[i]);
            var hash = CryptoTools.hashSHA256(combinedAttributeSalt);
            System.out.println("Hash: " + Arrays.toString(hash));

            list[i] = hash;
            System.out.println("Add hash to list: " + Arrays.toString(list));

            combinedHashes =  CryptoTools.combineByteArrays(combinedHashes, hash);
            System.out.println("Combined hashes: " + Arrays.toString(combinedHashes));
            System.out.println("Combined hashes length: " + combinedHashes.length);
        }
        finalHash = CryptoTools.hashSHA256(combinedHashes);
        System.out.println("FinalHash: " + Arrays.toString(finalHash));

    }

    private void generateAuthenticationPath(int[] index) {



    }

}
