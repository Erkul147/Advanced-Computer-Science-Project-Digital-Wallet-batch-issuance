package IHV;

import DataObjects.VerifiableCredential;
import Helper.CryptoTools;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessagingDataObjects.RegistrationData;
import Messaging.MessagingDataObjects.RequestAttestationsData;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.ATTESTATION_ISSUED;
import static Messaging.MessageType.REQUEST_REGISTRATION;

public class PIDProvider extends Issuer {
    public PIDProvider(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(name, inbox, router);
        var payload = new RegistrationData(name, "PID", "CitizenCard", new String[]{"ID","lastname","givennames","dateofbirth","placeofbirth","nationality"}, getPublicKey());
        router.route(new Message<>(name, "Registrar", REQUEST_REGISTRATION, payload));
    }

    @Override
    protected void handle(Message<?> msg) {
        if (msg == null) return;
        switch (msg.type()) {
            case REQUEST_ATTESTATION -> {
                if (msg.payload() instanceof RequestAttestationsData(String id, String attestationType)) {
                    ArrayList<VerifiableCredential> vcs = sendPIDAttestations(attestationType, id);
                    router.route(new Message<>(name, msg.from(), ATTESTATION_ISSUED, vcs));
                }

            }

            case CERT_ISSUED -> {
                if (msg.from().equals("ACA") && msg.payload() instanceof X509Certificate cert) {
                    var attestationType = CryptoTools.getAttestationFromCertificate(cert);
                    accessCertificate.put(attestationType, cert);
                }
            }
        }
    }


    private ArrayList<VerifiableCredential> sendPIDAttestations(String attestationType, String ID) {
        // list to store proofs (use almost like a stack)

        if (!Objects.equals(attestationType, "CitizenCard")) {
            System.out.println("Attestation type not supported: " + attestationType);
            return null;
        }
        System.out.println("Issuer: Checking if the user has officially registered data.");

        // fake attributes
        String[] attributes = getPID(ID);

        if (attributes == null) return null;
        System.out.println("        Data has been found.");
        System.out.println("    Creating merkle tree attestations for " + attestationType + ".");

        return createBatchesOfMerkleTrees(attributes, attestationType);
    }


}
