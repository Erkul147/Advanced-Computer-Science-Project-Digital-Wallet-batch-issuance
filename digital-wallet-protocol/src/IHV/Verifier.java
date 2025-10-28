package IHV;

import Helper.CryptoTools;
import Helper.TrustedService;
import DataObjects.VerifiablePresentation;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.HashMap;

public class Verifier {

    public static HashMap<byte[], Integer> rootsVerified = new HashMap<>();

    public boolean verify(VerifiablePresentation presentation) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        System.out.println();
        System.out.println("Verification");

        // check expiry date
        // presentation.md.expiryDate

        // use same signature alg
        // presentation.md.signatureAlgorithm

        if (TrustedService.isProofRevoked(presentation.md.ID)) return false;

        // information from the presentation
        var disclosedAttribute = presentation.disclosedAttribute;
        var path = presentation.path;
        var signedRoot = presentation.signedRoot;


        System.out.println("disclosed attribute: " + new String(disclosedAttribute.value, StandardCharsets.UTF_8));
        System.out.println("disclosed salt: " + Arrays.toString(disclosedAttribute.salt));


        // hashing disclosed attribute with salt
        var combinedAttributes = CryptoTools.combineByteArrays(disclosedAttribute.value, disclosedAttribute.salt);
        var hash = CryptoTools.hashSHA256(combinedAttributes);

        // will loop over the list of hashes. each loop will compute a new hash that is used to compute the next node
        for (int i = 0; i < path.hashes.size(); i++) {
            System.out.println("Computed hash: " + Arrays.toString(hash));
            // if sibling is left then H(sibling, current node) else H(current node, sibling)
            hash = (path.isSiblingLeft.get(i)) ?
                    CryptoTools.hashSHA256(CryptoTools.combineByteArrays(path.hashes.get(i), hash)) :
                    CryptoTools.hashSHA256(CryptoTools.combineByteArrays(hash, path.hashes.get(i)));
        }
        System.out.println("root's hash computed: " + Arrays.toString(hash));
        System.out.println("signed root: " + Arrays.toString(signedRoot));

        // use computed root, the given signed root and the public key of a known issuer
        // to verify if the attribute and salt was a part of the root
        PublicKey pk = TrustedService.getPublicKey(presentation.issuer);
        var verified = CryptoTools.verifySignatureMessage(pk, hash, signedRoot);

        // if the root is verified then check if the root has been seen before,
        // if not add it to the system,
        // else increment the counter
        if (verified) {
            var count = rootsVerified.get(hash);
            if (count != null) count++;
            else count = 0;
            rootsVerified.put(hash, count);
        }

        return verified;
    }
}
