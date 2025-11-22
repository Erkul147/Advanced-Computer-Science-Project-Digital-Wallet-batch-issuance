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
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.REQUEST_REGISTRATION;

public class QEAAProvider extends Issuer {
    public QEAAProvider(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(name, inbox, router);
        var payload = new RegistrationData(name, "Issuer", "AgeProof", new String[]{">16", ">18", ">21", ">23"}, getPublicKey());
        router.route(new Message<>(name, "Registrar", REQUEST_REGISTRATION, payload));
    }

    @Override
    protected void handle(Message<?> msg) {
        if (msg == null) return;
        switch (msg.type()) {
            case REQUEST_ATTESTATION -> {
                if (msg.payload() instanceof RequestAttestationsData(String id, String attestationType)) {
                    ArrayList<VerifiableCredential> vcs = sendAttestations(attestationType, id);
                }
            }

            case CERT_ISSUED -> {
                if (msg.from().equals("Registrar") && msg.payload() instanceof X509Certificate cert) {
                    var attestationType = CryptoTools.getAttestationFromCertificate(cert);
                    accessCertificate.put(attestationType, cert);

                }
            }
        }
    }

    private ArrayList<VerifiableCredential> sendAttestations(String attestationType, String ID) {
        // contact authentic source to obtain data
        String[] PID = getPID(ID);
        if (PID == null) return null;
        int[] ages = new int[] {16, 18, 21, 23};
        String[] attributes = new String[ages.length];

        for (int i = 0; i < ages.length; i++) {
            attributes[i] = ages[i] + "," + PID[3];
        }

        if (attestationType.equals("AgeProof")) return null;

        return createBatchesOfMerkleTrees(attributes, attestationType);
    }
}
