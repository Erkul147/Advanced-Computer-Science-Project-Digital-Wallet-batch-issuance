package IHV;

import CommitmentSchemes.MerkleTree;
import DataObjects.MetaData;
import DataObjects.VerifiableCredential;
import Helper.CryptoTools;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessagingDataObjects.RegistrationData;
import Messaging.MessagingDataObjects.RequestAttestationsData;

import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.*;


public abstract class Issuer extends Entity {
    public final String country = "Denmark";

    // size of proof batches
    protected final int BATCHSIZE = 30;

    public HashMap<String, X509Certificate> accessCertificate = new HashMap<>();

    public Issuer(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(name, inbox, router);

    }

    protected ArrayList<VerifiableCredential> createBatchesOfMerkleTrees(String[] attributes, String attestationType) {
        ArrayList<VerifiableCredential> verifiableCredentials = new ArrayList<>();
        // create all attestation
        for (int i = 0; i < BATCHSIZE; i++) {

            // metadata
            MetaData metaData = new MetaData(UUID.randomUUID().toString(), getName(), country, "1-1-2030", attestationType, new Timestamp(System.currentTimeMillis()), "RSA");

            // create the payload
            MerkleTree tree = new MerkleTree(attributes);


            // signature of the root
            tree.signedRoot = CryptoTools.signMessage(getPrivateKey(), tree.root.hash);

            // add the proof the to list
            verifiableCredentials.add(new VerifiableCredential(attestationType, metaData, tree, this, accessCertificate.get(attestationType)));
        }
        System.out.println("        Last merkle tree's root: " + CryptoTools.printHash(verifiableCredentials.getLast().merkleTree().root.hash));
        System.out.println("    " + BATCHSIZE + " new attestations created.");

        return verifiableCredentials;
    }

}
