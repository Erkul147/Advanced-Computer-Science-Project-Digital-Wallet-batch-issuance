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
    private static ArrayList<Thread> threads = new ArrayList<>();

    public static void main(String[] args) {
        // mailboxes for all entities on network
        Map<String, BlockingQueue<Message<?>>> mailboxes = new HashMap<>();
        MessageRouter router = new MessageRouter(mailboxes);
        threads.add(new Thread(router));
        threads.getLast().start();
        sleep(1);

        startSystem(mailboxes, router);


    }

    private static void startSystem(Map<String, BlockingQueue<Message<?>>> mailboxes, MessageRouter router) {
        // using bouncy castle, and adding it as the provider
        //System.out.println("-----------------------------------------");
        //System.out.println("Adding the security provider");
        Security.addProvider(new BouncyCastleProvider());


        System.out.println("Scenario 1: Creating Registrar, TLP and ACA. Along with their certificates");
        // create mailboxes
        mailboxes.put("Registrar", new LinkedBlockingQueue<>());
        mailboxes.put("ACA", new LinkedBlockingQueue<>());
        mailboxes.put("TLP", new LinkedBlockingQueue<>());

        ArrayList<Entity> trustEntities = new ArrayList<>();

        TrustedListProvider TLP = new TrustedListProvider(mailboxes.get("TLP"), router);
        Registrar registrar = new Registrar(mailboxes.get("Registrar"), router);
        AccessCertificateAuthority ACA = new AccessCertificateAuthority(mailboxes.get("ACA"), router);

        trustEntities.add(TLP);
        trustEntities.add(registrar);
        trustEntities.add(ACA);

        // starting threads
        for (Entity entity : trustEntities) {
            threads.add(new Thread(entity));
            threads.getLast().start();
        }
        sleep(1);

        router.route(new Message<>("System", registrar.getName(), MessageType.CREATE_TA, ""));


        System.out.println("\nScenario 2: Creating issuer and verifier and certificate requests");


        ArrayList<Entity> entityArraysList = new ArrayList<>();

        mailboxes.put("PID", new LinkedBlockingQueue<>());
        mailboxes.put("Medical Body", new LinkedBlockingQueue<>());

        // create entities
        //System.out.println("\n-----------------------------------------");
        //System.out.println("Creating entities");



        Issuer issuer1 = new PIDProvider("PID", mailboxes.get("PID"), router);
        Verifier verifier1 = new Verifier("Medical Body", mailboxes.get("Medical Body"), router);


        entityArraysList.add(issuer1);
        entityArraysList.add(verifier1);


        for (Entity entity : entityArraysList) {
            threads.add(new Thread(entity));
            threads.getLast().start();
        }
        sleep(1);

        System.out.println("Scenario 3: Holder requests proof and verifies it");
        mailboxes.put("DK1234567", new LinkedBlockingQueue<>());
        Holder holder1 = new Holder("DK1234567", mailboxes.get("DK1234567"), router);

        threads.add(new Thread(holder1));
        threads.getLast().start();
        sleep(1);

        holder1.requestProof("CitizenCard", issuer1.getName());



        System.out.println("\nScenario 4: Holder presents proof to verifier");
        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});


        System.out.println("\n-----------------------------------------");

        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});
        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});
        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});
        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});
        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});
        verifier1.requestAttestationFromUser(holder1.getName(), "CitizenCard");

        System.out.println();

        long now =  System.currentTimeMillis();
        while (now + 1000 > System.currentTimeMillis()) {
            holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{1,2});
        }

        Verifier.checkUnlinkability();

    }
    public static void sleep(int s) {
        try {
            Thread.sleep(1000L *s);
        } catch (InterruptedException _) {}
    }
}
