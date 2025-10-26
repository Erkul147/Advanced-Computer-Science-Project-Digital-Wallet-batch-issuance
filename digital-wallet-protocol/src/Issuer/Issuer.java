package Issuer;

import Helper.CryptoTools;
import Helper.TrustedService;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

public class Issuer {
    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair = CryptoTools.generateAsymmentricalKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();

    // name of issuer
    public String name;

    private String country = "Denmark";

    // size of proof batches
    private final int BATCHSIZE = 30;

    public Issuer(String name) {
        this.name = name;
    }

    private String[] getPID(String ID) {
        try {
            System.out.println(System.getProperty("user.dir"));
            BufferedReader br = new BufferedReader(new FileReader("digital-wallet-protocol/src/Issuer/attributes.csv"));

            for (String line = br.readLine(); line != null; line = br.readLine() ) {
                if  (line.contains(ID)) {
                    System.out.println(line);
                    return line.split(",");
                }
            }
        } catch (Exception e) {
            System.err.println(e);
        }
        return null;
    }

    private ArrayList<Proof> sendProofs(String proofName, String ID) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // list to store proofs (use almost like a stack)
        ArrayList<Proof> proofs = new ArrayList<>();

        // fake attributes
        String[] attributes = getPID(ID);
        if (attributes == null) return null;


        // create all proofs
        for (int i = 0; i < BATCHSIZE; i++) {
            var metaData = new MetaData(country, name, "1-1-2030", "RSA");

            // create the tree
            var tree = new MerkleTree(attributes);

            // sign the root of the tree
            var sign = CryptoTools.signMessage(privateKey, tree.root.hash);

            // add the proof the to list
            proofs.add(new Proof(proofName, metaData, tree, sign));
            System.out.println("Proof " + proofName + " " + (i+1) + " created. Root: " + Arrays.toString(proofs.getLast().merkleTree.root.hash));
        }
        System.out.println(BATCHSIZE + " new proofs created.");

        System.out.println();
        return proofs;
    }

    // used to imitate a request, there should be some authentication process of some kind
    public ArrayList<Proof> requestProof(String proofName, String ID) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return sendProofs(proofName, ID);
    }

    public boolean revokeAttestation(String attestationNo) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return TrustedService.addRevocation(attestationNo);
    }




}
