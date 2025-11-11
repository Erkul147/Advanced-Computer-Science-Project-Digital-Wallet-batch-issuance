package IHV;

import DataObjects.*;
import Helper.CryptoTools;
import Helper.Helper;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.sql.SQLOutput;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Holder {

    // contains a map of proofs. Each proof type will have single key, containing a list of proofs from that type
    Map<String, ArrayList<VerifiableCredential>> proofs = new HashMap<>();
    private String ID; // acts as a wallet bound ID from a PID issuer

    public Holder(String ID) {
        this.ID = ID;
    }

    // step 1: request a specific proof from an issuer
    public void requestProof(String attestationType, Issuer issuer) {
        System.out.println(attestationType + " proof requested");

        // add the proofs to a map
        ArrayList<VerifiableCredential> vc = issuer.requestProof(attestationType, ID);


        System.out.println("\nVerifying that the issuer is legit");
        if (verifyIssuer(issuer.accessCertificate.get(attestationType), presentProof(vc.getFirst(), new int[] {1}))) {
            System.out.println("Issuers signature is verified.");
        } else {
            System.out.println("Issuer is not verified");
            return;
        }

        proofs.put(attestationType, vc);
    }

    // step 4: verify issuer
    public boolean verifyIssuer(X509Certificate certificate, VerifiablePresentation vp) {

        String name = Helper.GetName(certificate);
        TrustedIssuerData trustedIssuer = TrustedListProvider.getTrustedIssuer(name);

        PublicKey certPublicKey = certificate.getPublicKey();
        PublicKey entityPublicKey = trustedIssuer.publicKey();

        if (!entityPublicKey.toString().equals(certPublicKey.toString())) {
            return false;
        }
        System.out.println("\nCertificate's public key matches trusted list's public key");

        byte[] signedRoot = vp.signedRoot();
        byte[] root = vp.root().hash;

        return CryptoTools.verifySignatureMessage(certPublicKey, root, signedRoot);
    }

    // step 5: present a VP
    public VerifiablePresentation presentProof(VerifiableCredential vc, int[] disclosedIndexes) {

        System.out.println("Presenting proof: " + vc.credentialType());

        System.out.println("Root of tree: " + CryptoTools.printHash(vc.merkleTree().root.hash));
        System.out.println("Signature of root: " + CryptoTools.printHash(vc.signedRoot()));
        System.out.println();


        //
        var tree = vc.merkleTree();

        DisclosedAttribute[] disclosedAttributes = new DisclosedAttribute[disclosedIndexes.length];
        // find the disclosed attributes and salts, the inclusion path and the signed root

        for (int i = 0; i < disclosedAttributes.length; i++) {
            var index =  disclosedIndexes[i];
            var disclosedAttribute = new DisclosedAttribute(tree, index);
            disclosedAttributes[i] = disclosedAttribute;
        }


        return new VerifiablePresentation(vc.metaData(), disclosedAttributes, vc.merkleTree().root, vc.signedRoot(), vc.metaData().issuerName(), vc.providerCertificate());
    }

    public VerifiableCredential getProof(String proofType) {
        ArrayList<VerifiableCredential> verifiableCredentials = proofs.get(proofType);
        if (verifiableCredentials == null || verifiableCredentials.isEmpty()) return null;

        VerifiableCredential vc = verifiableCredentials.getFirst();
        verifiableCredentials.remove(vc);
        
        System.out.println("Proofs left: " + verifiableCredentials.size());
        System.out.println();

        TrustedIssuerData issuer = TrustedListProvider.getTrustedIssuer(Helper.GetName(vc.providerCertificate()));

        // replace batch if list is empty
        if (verifiableCredentials.isEmpty()) requestProof(vc.credentialType(), issuer.issuer());

        return vc;
    }


}

