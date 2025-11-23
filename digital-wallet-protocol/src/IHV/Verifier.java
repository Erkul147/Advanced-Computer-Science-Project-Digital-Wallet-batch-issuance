package IHV;

import DataObjects.*;
import Helper.CryptoTools;
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
import java.util.*;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.*;

public class Verifier extends Entity {

    // RootsVerified acts as a database or a collection that store roots that are verified.
    // Will store every root from all verifiers. This is for unlinkability data.

    public HashMap<String, X509Certificate> accessCertificate = new HashMap<>();
    public static HashMap<String, ArrayList<VerifierDataCollection>> rootsVerified = new HashMap<>();
    
    public Verifier(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(name, inbox, router);
        var payload = new RegistrationData(name, "Verifier", "CitizenCard", new String[]{"ID","lastname","givennames","dateofbirth"}, getPublicKey());
        router.route(new Message<>(name, "Registrar", REQUEST_REGISTRATION, payload));

    }
    private HashMap<String, VerifiablePresentation> toVerify = new HashMap<>();

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
            case PRESENT_PRESENTATION -> {
                if (msg.payload() instanceof VerifiablePresentation VP) {
                    router.route(new Message<>(name, "TLP", VERIFY_CERT, VP));
                    toVerify.put(VP.md().ID(), VP);
                }
            }

            case ATTESTATION_VERIFIED -> {
                if (msg.payload() instanceof VerifiablePresentation VP) {
                    if (toVerify.containsKey(VP.md().ID())) {
                        //System.out.println("verifier has verified that attestation certificate comes from legit provider");
                        toVerify.remove(VP.md().ID());

                        var merkleProofVerified = verifyMerkleTree(VP);
                        if (merkleProofVerified) {
                            router.route(new Message<>(name, VP.subject(), ATTESTATION_VERIFIED, "access"));
                        } else {
                            router.route(new Message<>(name, VP.subject(), ERROR, "attestation not legit"));
                        }
                    }
                }
            }


        }
    }

    public void requestAttestationFromUser(String userID, String attestationType) {
        router.route(new Message<>(name, userID, REQUEST_ATTESTATION, attestationType));
    }

    public boolean verifyMerkleTree(VerifiablePresentation presentation) {
        System.out.println("\nVerifier: Verifying merkle proof");

        // verify all disclosed attributes
        DisclosedAttribute[] disclosedAttributes = presentation.disclosedAttributes();
        byte[] signedRoot = presentation.signedRoot();

        ArrayList<byte[]> hashesComputed = new ArrayList<>();

        byte[] finalHash = null;

        if (disclosedAttributes == null || disclosedAttributes.length == 0) return false;


        ArrayList<VerifierDataCollection> userData = null;
        String usersName = null;
        ArrayList<String> attributesValues = new ArrayList<>();

        for (int i = 0; i < disclosedAttributes.length; i++) {
            //System.out.println("    Following Merkle tree inclusion path:");

            DisclosedAttribute disclosedAttribute = presentation.disclosedAttributes()[i];
            InclusionPath path = disclosedAttribute.inclusionPath;


            String attributeValue = new String(disclosedAttribute.value, StandardCharsets.UTF_8);
            attributesValues.add(attributeValue);

            //System.out.println("        disclosed attribute: " + new String(disclosedAttribute.value, StandardCharsets.UTF_8));
            //System.out.println("        disclosed salt: " + CryptoTools.printHash(disclosedAttribute.salt));

            if (Objects.equals(disclosedAttribute.attributeName, "givennames")) {
                userData = rootsVerified.get(attributeValue);
                usersName = attributeValue;
            }

            // hashing disclosed attribute with salt
            byte[] combinedAttributes = CryptoTools.combineByteArrays(disclosedAttribute.value, disclosedAttribute.salt);
            byte[] hash = CryptoTools.hashSHA256(combinedAttributes);

            // will loop over the list of hashes. each loop will compute a new hash that is used to compute the next node
            for (int j = 0; j < path.hashes.size(); j++) {
                //System.out.println("        Computed hash: " + CryptoTools.printHash(hash));
                // if sibling is left then H(sibling, current node) else H(current node, sibling)
                hash = (path.isSiblingLeft.get(j)) ?
                        CryptoTools.hashSHA256(CryptoTools.combineByteArrays(path.hashes.get(j), hash)) :
                        CryptoTools.hashSHA256(CryptoTools.combineByteArrays(hash, path.hashes.get(j)));
            }
            //System.out.println("        root's hash computed: " + CryptoTools.printHash(hash));
            //System.out.println();
            hashesComputed.add(hash);




            // if this hash does not equal the first, the root is not the same, and we cannot verify the tree
            if (!Arrays.toString(hash).equals(Arrays.toString(hashesComputed.getFirst()))) return false;


            finalHash = hash;
        }
        //System.out.println("    signed root: " + CryptoTools.printHash(signedRoot));



        // use computed root, the given signed root and the public key from the certificate provided which is a known issuer
        // to verify if the attribute and salt was a part of the root
        PublicKey publicKey = presentation.providerCertificate().getPublicKey();
        boolean verified = CryptoTools.verifySignatureMessage(publicKey, finalHash, signedRoot);
        if (verified) System.out.println("Attestation has been verified");
        else  System.out.println("Attestation has NOT been verified");
        if (!verified) return false;

        // UNLINKABILITY CHECK:
        // if the root is verified then check if the root has been seen before,
        // if not add it to the "database",
        // else increment the counter. the counter shows the amount of times a root has been seen
        if (userData == null) userData = new ArrayList<>();
        userData.add(new VerifierDataCollection(attributesValues, CryptoTools.printHash(finalHash), String.valueOf(presentation.md().timestamp())));
        rootsVerified.put(usersName,  userData);


        return true;
    }
    
    public static void checkUnlinkability() {
        var msg = (Issuer.batchIssuance) ? "\nBATCH ISSUANCE WAS ENABLED" : "\nBATCH ISSUANCE WAS DISABLED";
        System.out.println(msg);

        var keys = rootsVerified.keySet();
        String attestationRoots = null;
        int attestationRootsSeen = 0;
        for (var key : keys) {
            ArrayList<VerifierDataCollection> dataCollected = rootsVerified.get(key);
            System.out.println(key + " has been seen " + dataCollected.size() + " times.");
            for (VerifierDataCollection data : dataCollected) {
                if (attestationRoots == null) {
                    attestationRoots = data.root();
                    attestationRootsSeen++;
                }
                if (!Objects.equals(attestationRoots, data.root())) attestationRootsSeen++;
            }
        }

        System.out.println("System has recognized " + keys.size() + " holder(s).");
        System.out.println("Different attestation roots seen: " +  attestationRootsSeen);
    }
}
