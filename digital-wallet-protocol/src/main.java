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

        mailboxes.put("PID", new LinkedBlockingQueue<>());
        mailboxes.put("AgeProver", new LinkedBlockingQueue<>());
        mailboxes.put("Verifier1", new LinkedBlockingQueue<>());
        mailboxes.put("Verifier2", new LinkedBlockingQueue<>());
        mailboxes.put("DK1234567", new LinkedBlockingQueue<>());

        // create entities
        System.out.println("\n-----------------------------------------");
        System.out.println("Creating entities");



        Issuer issuer1 = new PIDProvider("PID", mailboxes.get("PID"), router);
        Issuer issuer2 = new QEAAProvider("AgeProver", mailboxes.get("AgeProver"), router);
        Verifier verifier1 = new Verifier("Verifier1", mailboxes.get("Verifier1"), router);
        Verifier verifier2 = new Verifier("Verifier2", mailboxes.get("Verifier2"), router);
        Holder holder1 = new Holder("DK1234567", mailboxes.get("DK1234567"), router);


        entityArraysList.add(issuer1);
        entityArraysList.add(issuer2);
        entityArraysList.add(verifier1);
        entityArraysList.add(verifier2);
        entityArraysList.add(holder1);


        // starting threads and then sending a starting message to kick the system off
        for (Entity entity : entityArraysList) {
            new Thread(entity).start();
        }

        System.out.println("\n-----------------------------------------");
        holder1.requestProof("CitizenCard", issuer1.getName());

        sleep(1);

        System.out.println("\n-----------------------------------------");
        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});


        sleep(1);
        System.out.println("\n-----------------------------------------");
        verifier1.requestAttestationFromUser(holder1.getName(), "CitizenCard");
    }
    public static void sleep(int s) {
        try {
            Thread.sleep(1000*s);
        } catch (InterruptedException _) {}
    }
}
