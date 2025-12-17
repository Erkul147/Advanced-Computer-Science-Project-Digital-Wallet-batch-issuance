import IHV.*;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
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
        ArrayList<Entity> entityArraysList = new ArrayList<>();

        mailboxes.put("PID", new LinkedBlockingQueue<>());
        mailboxes.put("Medical Body", new LinkedBlockingQueue<>());
        mailboxes.put("WeChat", new LinkedBlockingQueue<>());
        mailboxes.put("WeChat2", new LinkedBlockingQueue<>());


        Issuer issuer1 = new PIDProvider("PID", mailboxes.get("PID"), router);
        Verifier verifier1 = new Verifier("Medical Body", mailboxes.get("Medical Body"), router);
        MalignVerifier malignVerifier = new MalignVerifier("WeChat", mailboxes.get("WeChat"), router);
        MalignVerifier malignVerifier2 = new MalignVerifier("WeChat2", mailboxes.get("WeChat2"), router);

        entityArraysList.add(issuer1);
        entityArraysList.add(verifier1);
        entityArraysList.add(malignVerifier);
        entityArraysList.add(malignVerifier2);


        for (Entity entity : entityArraysList) {
            threads.add(new Thread(entity));
            threads.getLast().start();
        }
        sleep(1);



        // System.out.println("Scenario 1: Holder requests proof and verifies it");

        mailboxes.put("DK1234567", new LinkedBlockingQueue<>());
        mailboxes.put("DK2345678", new LinkedBlockingQueue<>());

        Holder holder1 = new Holder("DK1234567", mailboxes.get("DK1234567"), router);
        Holder holder2 = new Holder("DK2345678", mailboxes.get("DK2345678"), router);



        threads.add(new Thread(holder1));
        threads.getLast().start();
        holder1.requestProof("CitizenCard", issuer1.getName());

        threads.add(new Thread(holder2));
        threads.getLast().start();
        holder2.requestProof("CitizenCard", issuer1.getName());


        sleep(1);

/*
        System.out.println("\nScenario 2: Holder presents proof to verifier");
        holder1.presentProof("CitizenCard", verifier1.getName(), new int[]{0, 1,2});


        System.out.println("\n-----------------------------------------");

        // verifier1.requestAttestationFromUser(holder1.getName(), "CitizenCard");
*/
        System.out.println("\nSCENARIO: \nOne MalignVerifier steals data from two holders");

        for (int i = 0; i < 30; i++) {
            holder1.presentProof("CitizenCard", malignVerifier.getName(), new int[]{0,1,2});
        }

        for (int i = 0; i < 30; i++) {
            holder2.presentProof("CitizenCard", malignVerifier.getName(), new int[]{0,1,2});
        }

        sleep(5);
        malignVerifier.checkUnlinkability();

    }

    public static void sleep(int s) {
        try {
            Thread.sleep(1000L *s);
        } catch (InterruptedException _) {}
    }
}
