package IHV;

import CommitmentSchemes.MerkleTree;
import DataObjects.MetaData;
import DataObjects.VerifiableCredential;
import Helper.CryptoTools;
import Helper.TrustedService;
import jdk.jshell.spi.ExecutionControl;

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

    //  https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/881984686/Wallet+for+Issuers
    // Issuing document step 2 and 3. (We have not included authentication data yet. We need public and private keys to create holder DID that PID can bind to the wallet.)
    // the csv file acts as a secure data registry
    private String[] getPID(String ID) {
        System.out.println(System.getProperty("user.dir"));
        try {
            // create buffered reader that reads the csv
            BufferedReader br = new BufferedReader(new FileReader("src/attributes.csv"));

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

    //  https://ec.europa.eu/digital-building-blocks/sites/spaces/EUDIGITALIDENTITYWALLET/pages/881984686/Wallet+for+Issuers
    // Issuing document step 3.
    private ArrayList<VerifiableCredential> sendProofs(String proofName, String ID) {
        // list to store proofs (use almost like a stack)
        ArrayList<VerifiableCredential> verifiableCredentials = new ArrayList<>();

        // fake attributes
        String[] attributes = getPID(ID);
        if (attributes == null) return null;
        System.out.println("creating merkle tree proofs");
        String[] type = new String[]{"VerifiableCredential", proofName};

        // create all proofs
        for (int i = 0; i < BATCHSIZE; i++) {

            // metadata
            MetaData metaData = new MetaData(name, country, type.clone(), "1-1-2030", "RSA");

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
    public ArrayList<VerifiableCredential> requestProof(String proofName, String ID) {
        return sendProofs(proofName, ID);
    }

    //TODO:
    public boolean authenticateUserIdentity() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public boolean revokeAttestation(String attestationNo) {
        return DataRegistry.addRevocation(attestationNo);
    }




}
