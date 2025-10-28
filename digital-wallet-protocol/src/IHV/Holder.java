package IHV;

import DataObjects.DisclosedAttribute;
import DataObjects.VerifiableCredential;
import DataObjects.VerifiablePresentation;
import Helper.InclusionPath;
import Helper.TrustedService;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Holder {

    // contains a map of proofs. Each proof type will have single key, containing a list of proofs from that type
    Map<String, ArrayList<VerifiableCredential>> proofs = new HashMap<>();

    // request a specific proof from an issuer
    public void requestProof(String proofName, Issuer issuer) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        System.out.println(proofName + " proof requested");
        // add the proofs to a map of proofs
        proofs.put(proofName, issuer.requestProof(proofName, "DK6789012"));
    }

    // presenting a proof
    public VerifiablePresentation presentProof(String proofName, int index) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

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
        if (proofs.isEmpty()) requestProof(proofName, TrustedService.issuers.get("GovernmentBody0"));

        //
        var tree = proof.merkleTree;

        // present the disclosed attribute and salt, the inclusion path and the signed root
        var disclosedAttributes = new DisclosedAttribute(tree.salts[index], tree.attributes[index].getBytes());
        InclusionPath path = tree.generateInclusionPath(index);


        return new VerifiablePresentation(proof.metaData, disclosedAttributes, path, proof.signedRoot, "GovernmentBody0");
    }
}

