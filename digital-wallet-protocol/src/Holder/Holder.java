package Holder;

import Helper.CryptoTools;
import Helper.InclusionPath;
import Issuer.Issuer;
import Issuer.Proof;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class Holder {
    Map<String, ArrayList<Proof>> proofs = new HashMap<>();

    public void requestProof(String proofName, Issuer issuer) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        System.out.println(proofName + " proof requested");
         proofs.put(proofName, issuer.requestProof(proofName));
    }

    public PresentationProof presentProof(String proofName, int index) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        var proofs = this.proofs.get(proofName);
        var proof = proofs.getFirst();
        proofs.removeFirst();


        System.out.println("Presenting proof: " + proofName);
        System.out.println(proofs.size() + " proofs left.");

        System.out.println("Root of tree: " + Arrays.toString(proof.merkleTree.root.hash));

        // replace batch
        if (proofs.isEmpty()) requestProof(proofName, proof.issuer);

        var tree = proof.merkleTree;

        var disclosedAttributes = new DisclosedAttribute<>(tree.salts[index], tree.attributes[index].getBytes());
        InclusionPath path = CryptoTools.generateInclusionPath(tree, index);


        return new PresentationProof(disclosedAttributes, path, proof.signedRoot, proof.issuer);
    }



}

