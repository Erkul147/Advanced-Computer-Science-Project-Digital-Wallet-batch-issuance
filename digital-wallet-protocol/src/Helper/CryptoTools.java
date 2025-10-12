package Helper;

import Issuer.MerkleTree;
import Issuer.Node;

import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

public class CryptoTools {
    private static final SecureRandom RANDOM = new SecureRandom();

    static KeyPairGenerator generator;
    static {
        try {
            generator = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPair generateAsymmentricalKeys() {
        return generator.generateKeyPair();
    }

    public static byte[] generateSalt(int byteLength) {
       byte[] salt = new byte[byteLength];
       RANDOM.nextBytes(salt);
       return salt;
    }

    public static byte[] hash(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(message);
        return md.digest();
    }

    public static byte[] combineByteArrays(byte[] b1, byte[] b2) {
        // if b1 = [1,2,3], b2 = [4,5,6]
        byte[] result = new byte[b1.length + b2.length]; // output: [0, 0, 0, 0, 0, 0]

        // use system to "concatenate" the arrays
        System.arraycopy(b1, 0, result, 0, b1.length); // output: [1, 2, 3, 0, 0, 0]
        System.arraycopy(b2, 0, result, b1.length, b2.length); // output: [1, 2, 3, 4, 5, 6]

        return result;
    }


    public static byte[] signMessage(PrivateKey key, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        var sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(key, RANDOM);
        sig.update(message);

        return sig.sign();
    }

    public static boolean verifySignatureMessage(PublicKey key, byte[] message, byte[] signedMessage) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        var sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(key);
        sig.update(message);

        return sig.verify(signedMessage);
    }

    public static InclusionPath generateInclusionPath(MerkleTree merkleTree, int index) {
        var tree = merkleTree.tree;
        Node currentNode = tree.getFirst().get(index);
        InclusionPath path = new InclusionPath();

        while(currentNode.parent != null) {
            var parent = currentNode.parent;
            var siblingIsLeft = (parent.children[0] != currentNode);
            var siblingHash = (siblingIsLeft) ? parent.children[0].hash : parent.children[1].hash;

            path.addPath(siblingHash, siblingIsLeft);
            currentNode = parent;
        }

        return path;
    }
}

