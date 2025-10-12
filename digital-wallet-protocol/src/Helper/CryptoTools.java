package Helper;

import Issuer.MerkleTree;
import Issuer.Node;

import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

public class CryptoTools {
    // secure random used to generate random bytes
    private static final SecureRandom RANDOM = new SecureRandom();

    // generator to generate keypairs (RSA for now)
    static KeyPairGenerator generator;
    static {
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // method to generate asymmetric keypairs using the generator
    public static KeyPair generateAsymmentricalKeys() {
        return generator.generateKeyPair();
    }

    // generate a random salt, with a given byte length
    public static byte[] generateSalt(int byteLength) {
       byte[] salt = new byte[byteLength]; // instantiated to 0,0,0,0,....
       RANDOM.nextBytes(salt); // use random to randomize the byte array
       return salt;
    }

    // hash a byte array using SHA-256
    public static byte[] hash(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(message);
        return md.digest();
    }

    // combine two byte arrays
    public static byte[] combineByteArrays(byte[] b1, byte[] b2) {
        // if b1 = [1,2,3], b2 = [4,5,6]
        byte[] result = new byte[b1.length + b2.length]; // output: [0, 0, 0, 0, 0, 0]

        // use system to "concatenate" the arrays
        System.arraycopy(b1, 0, result, 0, b1.length); // output: [1, 2, 3, 0, 0, 0]
        System.arraycopy(b2, 0, result, b1.length, b2.length); // output: [1, 2, 3, 4, 5, 6]

        return result;
    }

    // using SHA256 with RSA to sign a message
    public static byte[] signMessage(PrivateKey key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        var sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key, RANDOM);
        sig.update(message);

        return sig.sign();
    }

    // check signatures using SHA256 with RSA to verify a message has been signed from a specific issuer, using their public key
    public static boolean verifySignatureMessage(PublicKey key, byte[] message, byte[] signedMessage) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        var sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(message);

        return sig.verify(signedMessage);
    }

    // generate inclusion paths needed to compute the root of a merkle tree from a given index
    public static InclusionPath generateInclusionPath(MerkleTree merkleTree, int index) {
        var tree = merkleTree.tree;

        // find the starting node
        Node currentNode = tree.getFirst().get(index);

        // instantiate an inclusion path object
        InclusionPath path = new InclusionPath();

        System.out.println("Generating inclusion path for index: " + index);
        System.out.println("path: ");

        while(currentNode.parent != null) {

            // find parent of the current node
            var parent = currentNode.parent;

            // check if sibling of the current node is child1(left) or child2(right)
            var siblingIsLeft = (parent.children[0] != currentNode);

            // find sibling node's hash
            var siblingHash = (siblingIsLeft) ? parent.children[0].hash : parent.children[1].hash;

            // add directional information and the hash of the sibling
            path.addPath(siblingHash, siblingIsLeft);
            System.out.println("Sibling hash: " + Arrays.toString(siblingHash) + ", left: " + siblingIsLeft);
            currentNode = parent;
        }

        return path;
    }
}

