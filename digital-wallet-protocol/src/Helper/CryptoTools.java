package Helper;

import java.security.*;

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

    public static boolean verifyMessage(PublicKey key, byte[] message, byte[] signedMessage) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        var sig = Signature.getInstance("SHA256withRSA");

        sig.initVerify(key);
        sig.update(message);

        return sig.verify(signedMessage);
    }



    

}
