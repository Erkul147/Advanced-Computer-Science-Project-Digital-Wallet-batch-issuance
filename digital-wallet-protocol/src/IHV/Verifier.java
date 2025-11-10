package IHV;

import DataObjects.TrustedEntity;
import Helper.CryptoTools;
import DataObjects.VerifiablePresentation;
import Helper.DataRegistry;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Verifier {
    private final KeyPair keyPair = CryptoTools.generateAsymmetricKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();

    // RootsVerified acts as a database or a collection that store roots that are verified.
    // Will store every root from all verifiers. This is for unlinkability data.

    public String name;
    public X509Certificate accessCertificate;
    public static HashMap<byte[], Integer> rootsVerified = new HashMap<>();

    public Verifier(String name) {
        this.name = name;
    }

    public void requestAccessCertificate(String attestationType, String[] attributesRequest) {
        accessCertificate = TrustedListProvider.registrar.registerVerifier(publicKey, name, attestationType, attributesRequest);
    }

    public boolean verifyCertificate(X509Certificate certificate) {
        TrustedEntity trustedEntity = TrustedListProvider.getTrustedtrustedEntity(certificate.getSerialNumber().toString());

        // Check if entity exists
        if (trustedEntity == null) {
            System.out.println("Certificate not found in trusted entities.");
            return false;
        }

        X509Certificate trustedCert = trustedEntity.getX509CertificateInfo();

        if (trustedCert != null &&
                trustedCert.getSerialNumber().equals(certificate.getSerialNumber()) &&
                trustedCert.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) {

            if (trustedEntity.getStatus() != null && trustedEntity.getStatus()) {
                try {
                    certificate.checkValidity();
                    return true; // certificate is trusted and valid
                } catch (Exception e) {
                    e.printStackTrace();
                    return false;
                }
            } else  {
                System.out.print("Trusted Certificate is not valid");
                return false;
            }
        }

        return false; // Not valid
    }

    public boolean verifyMerkleTree(VerifiablePresentation presentation) {
        System.out.println("Verifying certificate");
        verifyCertificate(presentation.providerCertificate);


        System.out.println("Verification");



        // check expiry date
        // presentation.md.expiryDate

        // use same signature alg
        // presentation.md.signatureAlgorithm

        if (DataRegistry.isProofRevoked(presentation.md.ID)) return false;

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

        // use computed root, the given signed root and the public key from the certificate provided which is a known issuer
        // to verify if the attribute and salt was a part of the root
        PublicKey pk = presentation.providerCertificate.getPublicKey();
        var verified = CryptoTools.verifySignatureMessage(pk, hash, signedRoot);

        // UNLINKABILITY CHECK:
        // if the root is verified then check if the root has been seen before,
        // if not add it to the "database",
        // else increment the counter. the counter shows the amount of times a root has been seen
        if (verified) {
            var count = rootsVerified.get(hash);
            if (count != null) count++;
            else count = 0;
            rootsVerified.put(hash, count);
        }

        return verified;
    }
}
