package Issuer;

import Helper.CryptoTools;

import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

public class Issuer {
    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair = CryptoTools.generateAsymmentricalKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();

    // name of issuer
    public String name;

    // size of proof batches
    private final int BATCHSIZE = 30;

    public Issuer(String name) {
        this.name = name;
    }

    private ArrayList<Proof> sendProofs(String proofname) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // list to store proofs (use almost like a stack)
        ArrayList<Proof> proofs = new ArrayList<>();

        // create all proofs
        for (int i = 0; i < BATCHSIZE; i++) {
            // fake attributes
            String[] attributes = new String[] {"a", "b", "c", "d","e","f", "7", "8", "9", "10", "11"};

            // create the tree
            var tree = new MerkleTree(attributes);

            // sign the root of the tree
            var sign = CryptoTools.signMessage(privateKey, tree.root.hash);

            // add the proof the to list
            proofs.add(new Proof(proofname, tree, sign, this));
            System.out.println("Proof " + proofname + " " + (i+1) + " created. Root: " + Arrays.toString(proofs.getLast().merkleTree.root.hash));
        }
        System.out.println(BATCHSIZE + " new proofs created.");

        System.out.println();
        return proofs;
    }

    // used to imitate a request, there should be some authentication process of some kind
    public ArrayList<Proof> requestProof(String proofname) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return sendProofs(proofname);
    }
}
