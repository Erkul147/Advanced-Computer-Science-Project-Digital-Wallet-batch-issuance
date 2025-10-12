package Verifier;

import Helper.CryptoTools;
import Holder.PresentationProof;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;

public class Verifier {

    public static HashMap<byte[], Integer> rootsVerified = new HashMap<>();

    public boolean verify(PresentationProof presentation) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        System.out.println("Verification");


        var disclosedAttribute = presentation.disclosedAttribute;
        var path = presentation.path;
        var signedRoot = presentation.signedRoot;


        System.out.println("disclosed attribute: " + new String(disclosedAttribute.value, StandardCharsets.UTF_8));


        // hashing first disclosed attribute
        var combinedAttributes = CryptoTools.combineByteArrays(disclosedAttribute.value, disclosedAttribute.salt);
        var hash = CryptoTools.hash(combinedAttributes);

        for (int i = 0; i < path.hashes.size(); i++) {
            hash = (path.isSiblingLeft.get(i)) ?
                    CryptoTools.hash(CryptoTools.combineByteArrays(path.hashes.get(i), hash)) :
                    CryptoTools.hash(CryptoTools.combineByteArrays(hash, path.hashes.get(i)));
        }
        System.out.println("hash computed: " + Arrays.toString(hash));
        System.out.println("signed root: " + Arrays.toString(signedRoot));

        var verified = CryptoTools.verifySignatureMessage(presentation.issuer.publicKey, hash, signedRoot);

        if (verified) {
            var count = rootsVerified.get(hash);
            if (count != null) count++;
            else count = 0;

            rootsVerified.put(hash, count);
        }

        return verified;
    }
}
