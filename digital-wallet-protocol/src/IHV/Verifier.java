package IHV;

import DataObjects.DisclosedAttribute;
import DataObjects.InclusionPath;
import DataObjects.TrustedIssuerData;
import Helper.CryptoTools;
import DataObjects.VerifiablePresentation;
import Helper.Helper;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

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
        System.out.println("    Verifier " + name + " created.");
    }

    public void requestAccessCertificate(String attestationType, String[] attributesRequest) {
        accessCertificate = TrustedListProvider.registrar.registerVerifier(publicKey, name, attestationType, attributesRequest);
    }

    public boolean verifyCertificate(X509Certificate certificate, String attestationType) {
        System.out.println("    Finding issuer data from fake EU trusted lists. Issuer name from certificate: " + Helper.GetName(certificate));
        TrustedIssuerData trustedIssuer = TrustedListProvider.getTrustedIssuer(Helper.GetName(certificate));

        // Check if entity exists
        if (trustedIssuer == null) {
            System.out.println("    Certificate not found in trusted entities.");
            return false;
        }

        String fromCertificateAttestation = CryptoTools.getAttestationFromCertificate(certificate);


        System.out.println("    Attestation type received from holder: " + attestationType);
        System.out.println("    Attestation type obtained from the trusted list: " + fromCertificateAttestation);



        X509Certificate trustedCert = trustedIssuer.certificateMap().get(attestationType);

        if (trustedCert != null &&
            trustedCert.getPublicKey().equals(certificate.getPublicKey()) &&
            trustedCert.getSerialNumber().equals(certificate.getSerialNumber()) &&
            trustedCert.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) {
            try {
                // built in method to check if certificate is valid
                System.out.println("        Checking certificate: public key, id and name verified.");
                certificate.checkValidity();
                return true; // certificate is trusted and valid
            } catch (Exception e) {
                e.printStackTrace();
                return false;
            }
        }
        System.out.println("    Certificate verification failed");
        return false; // Not valid
    }

    public boolean verifyMerkleTree(VerifiablePresentation presentation) {
        System.out.println("    Verifier: Verifying certificate");
        if (!verifyCertificate(presentation.providerCertificate(), presentation.md().attestationType())) {
            System.out.println("        Invalid attestation type");
            return false;
        }
        System.out.println("    Certificate verified\n");

        if (TrustedListProvider.isProofRevoked(presentation.md().ID())) return false;

        // verify all disclosed attributes
        DisclosedAttribute[] disclosedAttributes = presentation.disclosedAttributes();
        byte[] signedRoot = presentation.signedRoot();

        ArrayList<byte[]> hashesComputed = new ArrayList<>();

        byte[] finalHash = null;

        if (disclosedAttributes == null || disclosedAttributes.length == 0) return false;
        for (int i = 0; i < disclosedAttributes.length; i++) {
            System.out.println("\n  Following Merkle tree inclusion path:");

            DisclosedAttribute disclosedAttribute = presentation.disclosedAttributes()[i];
            InclusionPath path = disclosedAttribute.inclusionPath;


            System.out.println("      disclosed attribute: " + new String(disclosedAttribute.value, StandardCharsets.UTF_8));
            System.out.println("      disclosed salt: " + CryptoTools.printHash(disclosedAttribute.salt));


            // hashing disclosed attribute with salt
            byte[] combinedAttributes = CryptoTools.combineByteArrays(disclosedAttribute.value, disclosedAttribute.salt);
            byte[] hash = CryptoTools.hashSHA256(combinedAttributes);

            // will loop over the list of hashes. each loop will compute a new hash that is used to compute the next node
            for (int j = 0; j < path.hashes.size(); j++) {
                System.out.println("        Computed hash: " + CryptoTools.printHash(hash));
                // if sibling is left then H(sibling, current node) else H(current node, sibling)
                hash = (path.isSiblingLeft.get(j)) ?
                        CryptoTools.hashSHA256(CryptoTools.combineByteArrays(path.hashes.get(j), hash)) :
                        CryptoTools.hashSHA256(CryptoTools.combineByteArrays(hash, path.hashes.get(j)));
            }
            System.out.println("    root's hash computed: " + CryptoTools.printHash(hash));
            hashesComputed.add(hash);


            // if this hash does not equal the first, the root is not the same, and we cannot verify the tree
            if (!Arrays.toString(hash).equals(Arrays.toString(hashesComputed.getFirst()))) return false;


            finalHash = hash;
        }
        System.out.println("All paths lead to the same root");

        System.out.println("\nsigned root: " + CryptoTools.printHash(signedRoot));

        // use computed root, the given signed root and the public key from the certificate provided which is a known issuer
        // to verify if the attribute and salt was a part of the root
        PublicKey publicKey = presentation.providerCertificate().getPublicKey();
        boolean verified = CryptoTools.verifySignatureMessage(publicKey, finalHash, signedRoot);

        // UNLINKABILITY CHECK:
        // if the root is verified then check if the root has been seen before,
        // if not add it to the "database",
        // else increment the counter. the counter shows the amount of times a root has been seen
        if (verified) {
            Integer count = rootsVerified.get(finalHash);
            if (count != null) count++;
            else count = 0;
            rootsVerified.put(finalHash, count);
        }

        if (verified) System.out.println("Attestation has been verified");

        return verified;
    }
}
