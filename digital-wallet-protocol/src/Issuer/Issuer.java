package Issuer;

import Helper.CryptoTools;

import java.security.*;
import java.util.ArrayList;

public class Issuer {
    private KeyPair keyPair = CryptoTools.generateAsymmentricalKeys();
    private PrivateKey privateKey = keyPair.getPrivate();
    public PublicKey publicKey = keyPair.getPublic();
    public String name;

    public Issuer(String name) {
        this.name = name;
    }

    private ArrayList<Proof> sendProofs(String proofname) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        ArrayList<Proof> proofs = new ArrayList<>();
        for (int i = 0; i < 30; i++) {
            String[] attributes = new String[] {"a", "b", "c", "d","e","f", "7", "8", "9", "10", "11"};
            var tree = new MerkleTree(attributes);
            var sign = CryptoTools.signMessage(privateKey, tree.root.hash);
            proofs.add(new Proof(proofname, tree, sign, this));
            System.out.println("Proof " + proofname + " " + (i+1) + " created.");
        }


        return proofs;
    }

    public ArrayList<Proof> requestProof(String proofname) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return sendProofs(proofname);
    }
}
