package Helper;
import java.security.*;

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
    public static KeyPair generateAsymmetricKeys() {
        return generator.generateKeyPair();
    }

    // generate a random salt, with a given byte length
    public static byte[] generateSalt(int byteLength) {
       byte[] salt = new byte[byteLength]; // instantiated to 0,0,0,0,....
       RANDOM.nextBytes(salt); // use random to randomize the byte array
       return salt;
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

    // hash a byte array using SHA-256
    public static byte[] hashSHA256(byte[] message) {
        byte[] hashedMessage = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(message);
            hashedMessage = md.digest();
        } catch (NoSuchAlgorithmException e) {e.printStackTrace();}

        return hashedMessage;
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


}

