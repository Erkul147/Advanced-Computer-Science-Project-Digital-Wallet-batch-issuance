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

import static Helper.Helper.getAttributeNameFromAttestationTypeAndIndex;

public class Holder {

    // contains a map of proofs. Each proof type will have single key, containing a list of proofs from that type
    Map<String, ArrayList<VerifiableCredential>> proofs = new HashMap<>();
    private final String ID; // acts as a wallet bound ID from a PID issuer

    public Holder(String ID) {
        this.ID = ID;
    }

    // step 1: request a specific proof from an issuer
    public void requestProof(String attestationType, Issuer issuer) {
        System.out.println("    Holder: " + attestationType + " proof requested");

        // add the proofs to a map
        ArrayList<VerifiableCredential> vc = issuer.requestProof(attestationType, ID);


        System.out.println("\n    Holder: Verifying that the issuer is legit");
        var verifiableCredential = vc.getFirst();

        if (verifyIssuer(issuer.accessCertificate.get(attestationType), verifiableCredential.merkleTree().root.hash, verifiableCredential.signedRoot())) {
            System.out.println("        Issuer's signature is verified.");
        } else {
            System.out.println("        Issuer is not verified");
            return;
        }

        proofs.put(attestationType, vc);
    }

    // step 4: verify issuer
    public boolean verifyIssuer(X509Certificate certificate, byte[] root, byte[] signedRoot) {

        System.out.println("        Using certificate to find the ID of the issuer and find the issuer in the fake EU trusted lists.");
        String name = Helper.GetName(certificate);
        TrustedIssuerData trustedIssuer = TrustedListProvider.getTrustedIssuer(name);

        PublicKey certPublicKey = certificate.getPublicKey();
        PublicKey entityPublicKey = trustedIssuer.publicKey();

        System.out.println("            Checking if the public keys match");
        if (!entityPublicKey.toString().equals(certPublicKey.toString())) {
            System.out.println("\n            Certificate's public key does not match the trusted list's public key");
            return false;
        }
        System.out.println("\n        Public keys match");
        System.out.println("        Verifying root signature with public key.");
        return CryptoTools.verifySignatureMessage(certPublicKey, root, signedRoot);
    }

    // step 5: present a VP
    public VerifiablePresentation presentProof(VerifiableCredential vc, int[] disclosedIndexes) {

        System.out.println("Presenting proof: " + vc.credentialType());

        System.out.println("    Root of tree: " + CryptoTools.printHash(vc.merkleTree().root.hash));
        System.out.println("    Signature of root: " + CryptoTools.printHash(vc.signedRoot()));
        System.out.println();


        //
        var tree = vc.merkleTree();

        DisclosedAttribute[] disclosedAttributes = new DisclosedAttribute[disclosedIndexes.length];
        // find the disclosed attributes and salts, the inclusion path and the signed root

        for (int i = 0; i < disclosedAttributes.length; i++) {
            var index =  disclosedIndexes[i];
            var disclosedAttribute = new DisclosedAttribute(tree, index, Helper.getAttributeNameFromAttestationTypeAndIndex(vc.credentialType(), disclosedIndexes[i]));
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

