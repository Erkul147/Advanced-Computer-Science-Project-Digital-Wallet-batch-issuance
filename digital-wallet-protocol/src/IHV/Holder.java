package IHV;

import DataObjects.DisclosedAttribute;
import DataObjects.VerifiableCredential;
import DataObjects.VerifiablePresentation;
import DataObjects.InclusionPath;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Holder {

    // contains a map of proofs. Each proof type will have single key, containing a list of proofs from that type
    Map<String, ArrayList<VerifiableCredential>> proofs = new HashMap<>();
    private String ID; // acts as a wallet bound ID from a PID issuer

    public Holder(String ID) {
        this.ID = ID;
    }

    //  https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/881984686/Wallet+for+Issuers
    // Issuing document step 1.
    // request a specific proof from an issuer
    public void requestProof(String proofName, Issuer issuer) {
        System.out.println(proofName + " proof requested");

        // add the proofs to a map
        ArrayList<VerifiableCredential> vc = issuer.requestProof(proofName, ID);

        proofs.put(proofName, vc);
    }

    //  https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/881984686/Wallet+for+Issuers
    // Issuing document step 4.
    // TODO: implement a method for verifying the accuracy of the document.

    /*
    [Wallet] receives provider certificate
       │
       ├─ Verify signature with issuer public key
       ├─ Validate issuer chain up to trusted root CA
       ├─ Check validity period, revocation, extensions
       └─ If all pass → Provider is trusted
     */
    public boolean verifyCertificate() {

        throw new UnsupportedOperationException("Not supported yet.");
    }

    //  https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/881984686/Wallet+for+Issuers
    // Issuing document step 5.
    // presenting a proof
    public VerifiablePresentation presentProof(String proofName, int index) {

        // access the list of proofs from a proof type
        var proofs = this.proofs.get(proofName);

        // ONE TIME USE: get the first index of the list and remove it.
        if (proofs == null) return null;

        var proof = proofs.removeFirst();

        System.out.println("Presenting proof: " + proofName);
        System.out.println(proofs.size() + " proofs left.");

        System.out.println("Root of tree: " + Arrays.toString(proof.merkleTree.root.hash));
        System.out.println("Signature of root: " + Arrays.toString(proof.signedRoot));
        System.out.println();

        // replace batch if list is empty
        if (proofs.isEmpty()) requestProof(proofName, TrustedService.issuers.get(proof.metaData.issuerName));

        //
        var tree = proof.merkleTree;

        // present the disclosed attribute and salt, the inclusion path and the signed root
        var disclosedAttributes = new DisclosedAttribute(tree.salts[index], tree.attributes[index].getBytes());
        InclusionPath path = tree.generateInclusionPath(index);


        return new VerifiablePresentation(proof.metaData, disclosedAttributes, path, proof.signedRoot, proof.metaData.issuerName, proof.providerCertificate);
    }



}

