package IHV;

import CommitmentSchemes.MerkleTree;
import DataObjects.MetaData;
import DataObjects.VerifiableCredential;
import Helper.CryptoTools;
import Messaging.Message;
import Messaging.MessageRouter;

import java.security.*;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.REQUEST_REGISTRATION;


public class Issuer extends Entity {
    public final String country = "Denmark";

    // size of proof batches
    private final int BATCHSIZE = 30;

    public HashMap<String, X509Certificate> accessCertificate = new HashMap<>();

    public Issuer(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(name, inbox, router);
        System.out.println("Issuer " + name + " created.");
        router.route(new Message<>(name, "Registrar", REQUEST_REGISTRATION, "name:" + name + ",entityType:issuer,attestationType:citizencard" + ",attributes:a;b;c"));
    }

    @Override
    protected void handle(Message<?> msg) {

    }

    // step 3: send proofs to user
    private ArrayList<VerifiableCredential> sendAttestations(String attestationType, String ID) {
        // list to store proofs (use almost like a stack)
        ArrayList<VerifiableCredential> verifiableCredentials = new ArrayList<>();

        if (!Objects.equals(attestationType, "CitizenCard")) {
            System.out.println("Attestation type not supported: " + attestationType);
            return null;
        }
        System.out.println("    Issuer: Checking if the user has officially registered data.");
        // fake attributes
        String[] attributes = AuthenticSource.getPID(ID);

        if (attributes == null) return null;
        System.out.println("        Data has been found.");

        System.out.println("    Creating merkle tree attestations for " + attestationType + ".");
        String[] type = new String[]{"VerifiableCredential", attestationType};

        // create all attestation
        for (int i = 0; i < BATCHSIZE; i++) {

            // metadata
            MetaData metaData = new MetaData(UUID.randomUUID().toString(), getName(), country, type.clone(), "1-1-2030", attestationType, new Timestamp(System.currentTimeMillis()), "RSA");

            // create the payload
            MerkleTree tree = new MerkleTree(attributes);


            // signature of the root
            byte[] sign = CryptoTools.signMessage(getPrivateKey(), tree.root.hash);
            tree.signedRoot = sign;

            // add the proof the to list
            verifiableCredentials.add(new VerifiableCredential(attestationType, metaData, tree, this, accessCertificate.get(attestationType)));
        }
        System.out.println("        Last merkle tree's root: " + CryptoTools.printHash(verifiableCredentials.getLast().merkleTree().root.hash));
        System.out.println("    " + BATCHSIZE + " new attestations created.");

        return verifiableCredentials;
    }

    // used to imitate a request, there should be some authentication process of some kind
    public ArrayList<VerifiableCredential> requestProof(String proofName, String ID) {
        return sendAttestations(proofName, ID);
    }

    public boolean revokeAttestation(String attestationNo) {
        return TrustedListProvider.addRevocation(attestationNo);
    }


}
