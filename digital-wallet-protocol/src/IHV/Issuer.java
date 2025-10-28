package IHV;

import CommitmentSchemes.MerkleTree;
import DataObjects.MetaData;
import DataObjects.VerifiableCredential;
import Helper.CryptoTools;
import Helper.TrustedService;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;

public class Issuer {
    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair = CryptoTools.generateAsymmetricKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();

    // name of issuer
    public String name;

    public final String country = "Denmark";

    // size of proof batches
    private final int BATCHSIZE = 30;

    public Issuer(String name) {
        this.name = name;
    }

    // the csv file acts as a secure data registry
    private String[] getPID(String ID) {
        try {
            // create buffered reader that reads the csv
            BufferedReader br = new BufferedReader(new FileReader("digital-wallet-protocol/src/attributes.csv"));

            // fake query: find id
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

    private ArrayList<VerifiableCredential> sendProofs(String proofName, String ID) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        // list to store proofs (use almost like a stack)
        ArrayList<VerifiableCredential> verifiableCredentials = new ArrayList<>();

        // fake attributes
        String[] attributes = getPID(ID);
        if (attributes == null) return null;


        // create all proofs
        for (int i = 0; i < BATCHSIZE; i++) {

            // metadata
            MetaData metaData = new MetaData(country, name, "1-1-2030", "RSA");

            // create the payload
            MerkleTree tree = new MerkleTree(attributes);

            // signature of the root
            byte[] sign = CryptoTools.signMessage(privateKey, tree.root.hash);

            // add the proof the to list
            verifiableCredentials.add(new VerifiableCredential(proofName, metaData, tree, sign));
            System.out.println("Proof " + proofName + " " + (i+1) + " created. Root: " + Arrays.toString(verifiableCredentials.getLast().merkleTree.root.hash));
        }
        System.out.println(BATCHSIZE + " new proofs created.");

        System.out.println();
        return verifiableCredentials;
    }

    // used to imitate a request, there should be some authentication process of some kind
    public ArrayList<VerifiableCredential> requestProof(String proofName, String ID) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return sendProofs(proofName, ID);
    }

    public boolean revokeAttestation(String attestationNo) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        return TrustedService.addRevocation(attestationNo);
    }




}
