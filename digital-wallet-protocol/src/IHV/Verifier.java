package IHV;

import DataObjects.DisclosedAttribute;
import DataObjects.InclusionPath;
import DataObjects.TrustedIssuerData;
import Helper.CryptoTools;
import DataObjects.VerifiablePresentation;
import Helper.Helper;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;
import Messaging.MessagingDataObjects.RegistrationData;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.REQUEST_REGISTRATION;

public class Verifier extends Entity {

    // RootsVerified acts as a database or a collection that store roots that are verified.
    // Will store every root from all verifiers. This is for unlinkability data.

    public String name;
    public HashMap<String, X509Certificate> accessCertificate = new HashMap<>();
    public static HashMap<byte[], Integer> rootsVerified = new HashMap<>();

    public Verifier(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(name, inbox, router);
        System.out.println("Verifier " + name + " created.");
        var payload = new RegistrationData(name, "Verifier", "CitizenCard", new String[]{"a", "b", "c"}, getPublicKey());
        router.route(new Message<>(name, "Registrar", REQUEST_REGISTRATION, payload));

    }

    @Override
    protected void handle(Message<?> msg) {
        if (msg == null) return;
        switch (msg.type()) {
            case CERT_ISSUED -> {
                if (msg.from().equals("Registrar") && msg.payload() instanceof X509Certificate cert) {
                    var attestationType = CryptoTools.getAttestationFromCertificate(cert);
                    accessCertificate.put(attestationType, cert);

                }
            }



        }
    }


    public boolean verifyMerkleTree(VerifiablePresentation presentation) {
        System.out.println("    Verifier: Verifying certificate");
        if (!Helper.verifyCertificate(presentation.providerCertificate(), presentation.md().attestationType())) {
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
