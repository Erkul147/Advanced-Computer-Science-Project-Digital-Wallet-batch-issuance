import Helper.CryptoTools;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class main {
    
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String[] attributes = new String[] {"a", "b", "c","d","e","f", "7", "8", "9", "10", "11"};

        // proof
        // Issuer.MerkleTree merkleTree = new Issuer.MerkleTree(attributes);

        var hash = CryptoTools.hash(new byte[] {123});
        var keyPair = CryptoTools.generateAsymmentricalKeys();
        var signature = CryptoTools.signMessage(keyPair.getPrivate(), hash);

        System.out.println(CryptoTools.verifyMessage(keyPair.getPublic(), hash, signature));



    }


}
