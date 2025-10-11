import java.security.*;

public class CryptoTools {
    private static final SecureRandom RANDOM = new SecureRandom();
    
    public static byte[] generateSalt(int byteLength) {
       byte[] salt = new byte[byteLength];
       RANDOM.nextBytes(salt);
       return salt;
    }

    

}
