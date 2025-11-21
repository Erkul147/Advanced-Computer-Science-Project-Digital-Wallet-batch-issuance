import DataObjects.VerifiableCredential;
import DataObjects.VerifiablePresentation;
import Helper.CryptoTools;
import IHV.*;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class main {
    
    public static void main(String[] args) {
        // mailboxes for all entities on network
        Map<String, BlockingQueue<Message<?>>> mailboxes = new HashMap<>();
        MessageRouter router = new MessageRouter(mailboxes);

        startSystem(mailboxes, router);


    }

    private static void startSystem(Map<String, BlockingQueue<Message<?>>> mailboxes, MessageRouter router) {
        // using bouncy castle, and adding it as the provider
        System.out.println("-----------------------------------------");
        System.out.println("Adding the security provider");
        Security.addProvider(new BouncyCastleProvider());


        // create mailboxes
        mailboxes.put("Registrar", new LinkedBlockingQueue<>());
        mailboxes.put("ACA", new LinkedBlockingQueue<>());
        mailboxes.put("TLP", new LinkedBlockingQueue<>());

        ArrayList<Entity> trustEntities = new ArrayList<>();

        Registrar registrar = new Registrar(mailboxes.get("Registrar"), router);
        AccessCertificateAuthority ACA = new AccessCertificateAuthority(mailboxes.get("ACA"), router);
        TrustedListProvider TLP = new TrustedListProvider(mailboxes.get("TLP"), router);


        // add to list in order to start a thread for all entities in a loop
        trustEntities.add(registrar);
        trustEntities.add(ACA);
        trustEntities.add(TLP);

        // starting threads and then sending a starting message to kick the system off
        for (Entity entity : trustEntities) {
            new Thread(entity).start();
        }

        System.out.println("\n-----------------------------------------");
        System.out.println("Starting the system");
        router.route(new Message<>("System", registrar.getName(), MessageType.START, ""));
        try {
            System.out.println("Sleep start");
            Thread.sleep(1000);
            System.out.println("Sleep end");
        } catch (InterruptedException _) {}
        System.out.println("-----------------------------------------");


        ArrayList<Entity> entityArraysList = new ArrayList<>();

        mailboxes.put("Issuer1", new LinkedBlockingQueue<>());
        mailboxes.put("Issuer2", new LinkedBlockingQueue<>());
        mailboxes.put("Verifier1", new LinkedBlockingQueue<>());
        mailboxes.put("Verifier2", new LinkedBlockingQueue<>());
        mailboxes.put("Holder1", new LinkedBlockingQueue<>());

        // create entities
        System.out.println("\n-----------------------------------------");
        System.out.println("Creating entities");



        Issuer issuer1 = new Issuer("Issuer1", mailboxes.get("Issuer1"), router);
        Issuer issuer2 = new Issuer("Issuer2", mailboxes.get("Issuer2"), router);
        Verifier verifier1 = new Verifier("Verifier1", mailboxes.get("Verifier1"), router);
        Verifier verifier2 = new Verifier("Verifier2", mailboxes.get("Verifier2"), router);
        Holder holder1 = new Holder("Holder1", mailboxes.get("Holder1"), router);


        entityArraysList.add(issuer1);
        entityArraysList.add(issuer2);
        entityArraysList.add(verifier1);
        entityArraysList.add(verifier2);
        entityArraysList.add(holder1);


        // starting threads and then sending a starting message to kick the system off
        for (Entity entity : entityArraysList) {
            new Thread(entity).start();
        }

    }

/*

    private static void old() {

        // creating Registrar and Access Certificate Authority
        System.out.println("-----------------------------------------");
        System.out.println("Creating Registrar and CA");
        TrustedListProvider.registrar = new Registrar();

        // generate new issuers and verifier
        System.out.println("-----------------------------------------");
        System.out.println("Creating Issuers and Verifiers");

        Issuer[] issuers = new Issuer[] {
                new Issuer("GovernmentBody0"),
                new Issuer("GovernmentBody1")
        };

        Verifier[] verifiers = new  Verifier[] {
                new Verifier("Hospital"),
                new Verifier("Kiosk")
        };

        // issuers must specify which attestation they want to create and what info it must hold
        System.out.println("\n-----------------------------------------");
        System.out.println("Issuer0 request Access Certificate to create a Citizen card attestation.");
        issuers[0].requestAccessCertificate("CitizenCard", new String[] {"ID", "lastname", "givennames", "dateofbirth", "placeofbirth", "nationality"});

        // verifier must say which attestation they wish to request data from and what data
        System.out.println("\n-----------------------------------------");
        System.out.println("Verifier0 request Access Certificate to request attributes from a Citizen card attestation.");
        verifiers[0].requestAccessCertificate("CitizenCard", new String[] {"ID", "lastname", "givennames", "dateofbirth"});

        // create holder and request a proof
        System.out.println("\n-----------------------------------------");
        System.out.println("Creating a holder (Wallet).");
        Holder holder = new Holder("DK12345");

        System.out.println("User requesting an attestation (citizen card):");
        holder.requestProof("CitizenCard", issuers[0]);

        // present proof to a verifier
        System.out.println("\n-----------------------------------------");
        System.out.println("User creating a VP to show a verifier");
        VerifiableCredential proof = holder.getProof("CitizenCard");
        VerifiablePresentation VP = holder.presentProof(proof, new int[] {0,2});
        System.out.println(VP.toString());

        System.out.println("\n-----------------------------------------");
        System.out.println("Verifier receives VP and uses it to authenticate the attestation and attributes");
        verifiers[0].verifyMerkleTree(VP);

        System.out.println();
    }


    private static void testVerificationMerkleTree()  {

        var holder = new Holder("DK6789012");
        var verifier = new Verifier("Kiosk");

        // holder requesting proof from issuer
        holder.requestProof("CitizensCard", TrustedListProvider.getTrustedIssuer("GovernmentBody0").issuer());

        for (int i = 0; i < 2; i++) {
            System.out.println();
            // holder presenting proof to verifier

            VerifiableCredential proof = holder.getProof("CitizensCard");
            VerifiablePresentation presentation = holder.presentProof(proof, new int[] {2});

            // verification: true / false
            boolean verification = verifier.verifyMerkleTree(presentation);
            System.out.println("Holder has a valid proof: " + verification);
            System.out.println("-----------------------------------------");
        }

        System.out.println("unique roots: " + Verifier.rootsVerified.size());
        System.out.println("-----------------------------------------\n");

    }

    private static void testRevocation()  {

        System.out.println("creating holder");
        var holder = new Holder("DK6789012");

        System.out.println("creating verifier");
        var verifier = new Verifier("Kiosk");

        System.out.println("request proofs from issuer");
        // holder requesting proof from issuer
        holder.requestProof("CitizensCard", TrustedListProvider.getTrustedIssuer("GovernmentBody0").issuer());


        for (int i = 0; i < 2; i++) {
            System.out.println();
            // holder presenting proof to verifier
            VerifiableCredential proof = holder.getProof("CitizensCard");
            VerifiablePresentation presentation = holder.presentProof(proof, new int[] {2});

            TrustedListProvider.addRevocation(presentation.md().ID());


            // verification: true / false
            boolean verification = verifier.verifyMerkleTree(presentation);
            System.out.println("Holder has a valid proof: " + verification);
            System.out.println("-----------------------------------------");
            System.out.println();
        }

    }


 */

}
