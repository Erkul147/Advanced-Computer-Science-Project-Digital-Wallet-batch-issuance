package IHV;

import CommitmentSchemes.MerkleTree;
import DataObjects.*;
import Helper.CryptoTools;
import Helper.Helper;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;
import Messaging.MessagingDataObjects.RequestAttestationsData;

import java.security.PublicKey;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.sql.SQLOutput;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;

import static Helper.Helper.getAttributeNameFromAttestationTypeAndIndex;
import static Messaging.MessageType.*;

public class Holder extends Entity {

    // contains a map of proofs. Each proof type will have single key, containing a list of proofs from that type
    private Map<String, ArrayList<VerifiableCredential>> attestations = new HashMap<>();
    private final String ID; // acts as a wallet bound ID from a PID issuer
    private ArrayList<VerifiableCredential> unverifiedProofs = null;

    public Holder(String ID, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(ID, inbox, router);
        this.ID = ID;
    }
    @Override
    protected void handle(Message<?> msg) {

        if (msg == null) return;
        switch (msg.type()) {
            case ATTESTATION_ISSUED -> {
                try {
                    @SuppressWarnings("unchecked")
                    ArrayList<VerifiableCredential> vcs = (ArrayList<VerifiableCredential>) msg.payload();
                    unverifiedProofs = vcs;
                    VerifiableCredential example = vcs.getFirst();
                    X509Certificate certificate = example.providerCertificate();

                    router.route(new Message<>(name, "TLP", VERIFY_CERT, certificate));
                } catch (ClassCastException _) {
                }
            }
            case ATTESTATION_VERIFIED -> {
                if (unverifiedProofs != null && msg.payload() instanceof X509Certificate certificate) {
                    attestations.put(CryptoTools.getAttestationFromCertificate(certificate), unverifiedProofs);
                }
            }
            case REQUEST_ATTESTATION -> {
                if (msg.payload() instanceof String payload) {
                    presentProof(payload, msg.from(), new int[]{1, 2, 3});
                }
            }
        }
    }

    // step 1: request a specific proof from an issuer
    public void requestProof(String attestationType, String issuerName) {
        //System.out.println("Holder: " + attestationType + " attestations requested from " + issuerName);
        router.route(new Message<>(name, issuerName, REQUEST_ATTESTATION, new RequestAttestationsData(ID, attestationType)));
    }


    // step 5: present a VP
    public void presentProof(String attestationType, String verifierName, int[] disclosedIndexes) {
        //System.out.println("Presenting proof for " + attestationType + " attestations to " + verifierName);
        VerifiableCredential vc = getAttestation(attestationType);
        if (vc == null) {
            //System.out.println("no verifiable credential found for " + attestationType);
            return;
        };

        MerkleTree tree = vc.merkleTree();

        DisclosedAttribute[] disclosedAttributes = new DisclosedAttribute[disclosedIndexes.length];
        // find the disclosed attributes and salts, the inclusion path and the signed root

        for (int i = 0; i < disclosedAttributes.length; i++) {
            var index =  disclosedIndexes[i];
            DisclosedAttribute disclosedAttribute = new DisclosedAttribute(tree, index, Helper.getAttributeNameFromAttestationTypeAndIndex(vc.credentialType(), disclosedIndexes[i]));
            disclosedAttributes[i] = disclosedAttribute;
        }


        VerifiablePresentation VP = new VerifiablePresentation(vc.metaData(), disclosedAttributes, vc.merkleTree().root,
                vc.merkleTree().signedRoot, vc.metaData().issuerName(), name, vc.providerCertificate());

        router.route(new Message<>(name, verifierName, PRESENT_PRESENTATION, VP));
    }

    private VerifiableCredential getAttestation(String proofType) {
        ArrayList<VerifiableCredential> verifiableCredentials = attestations.get(proofType);
        if (verifiableCredentials == null || verifiableCredentials.isEmpty()) return null;

        VerifiableCredential vc = verifiableCredentials.getFirst();
        if (Issuer.batchIssuance) verifiableCredentials.remove(vc);

        //System.out.println("    Proofs left: " + verifiableCredentials.size());

        return vc;
    }
}

