package IHV;

import CommitmentSchemes.MerkleTree;
import DataObjects.MetaData;
import DataObjects.VerifiableCredential;
import Helper.CryptoTools;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.*;
import java.security.cert.X509Certificate;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

public class Issuer {
    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair = CryptoTools.generateAsymmetricKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();

    // name of issuer
    public String name;


    public final String country = "Denmark";

    // size of proof batches
    private final int BATCHSIZE = 31;

    public HashMap<String, X509Certificate> accessCertificate = new HashMap<>();

    public Issuer(String name) {
        System.out.println("Issuer " + name + " created.");
        this.name = name;
    }

    public void requestAccessCertificate(String attestationType, String[] attributesRequest) {
        X509Certificate accessCertificate = TrustedListProvider.registrar.registerIssuer(this, attestationType, attributesRequest);

        this.accessCertificate.put(attestationType, accessCertificate);
    }

    // step 2: obtain data
    private String[] getPID(String ID) {
        try {
            // create buffered reader that reads the csv
            BufferedReader br = new BufferedReader(new FileReader("digital-wallet-protocol/src/attributes.csv"));

            // fake query: find id
            for (String line = br.readLine(); line != null; line = br.readLine() ) {
                if  (line.contains(ID)) {
                    return line.split(",");
                }
            }
        } catch (Exception e) {
            System.err.println(e);
        }
        return null;
    }

    // step 3: send proofs to user
    private ArrayList<VerifiableCredential> sendAttestations(String attestationType, String ID) {
        // list to store proofs (use almost like a stack)
        ArrayList<VerifiableCredential> verifiableCredentials = new ArrayList<>();

        // fake attributes
        String[] attributes = getPID(ID);

        if (attributes == null) return null;

        System.out.println("creating merkle tree attestations\n");
        String[] type = new String[]{"VerifiableCredential", attestationType};

        // create all attestation
        for (int i = 0; i < BATCHSIZE; i++) {

            // metadata
            MetaData metaData = new MetaData(UUID.randomUUID().toString(), name, country, type.clone(), "1-1-2030", attestationType, new Timestamp(System.currentTimeMillis()), "RSA");

            // create the payload
            MerkleTree tree = new MerkleTree(attributes);

            // signature of the root
            byte[] sign = CryptoTools.signMessage(privateKey, tree.root.hash);

            // add the proof the to list
            verifiableCredentials.add(new VerifiableCredential(attestationType, metaData, tree, sign, this, accessCertificate.get(attestationType)));
            System.out.println("Attestation " + attestationType + " " + (i+1) + " created. Root: " + CryptoTools.printHash(verifiableCredentials.getLast().merkleTree().root.hash));
        }
        System.out.println(BATCHSIZE + " new attestations created.");

        System.out.println();
        return verifiableCredentials;
    }

    // used to imitate a request, there should be some authentication process of some kind
    public ArrayList<VerifiableCredential> requestProof(String proofName, String ID) {
        return sendAttestations(proofName, ID);
    }

    public boolean revokeAttestation(String attestationNo) {
        return TrustedListProvider.addRevocation(attestationNo);
    }

}
