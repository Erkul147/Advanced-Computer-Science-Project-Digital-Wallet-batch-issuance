package IHV;

import Helper.CryptoTools;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.SEND_PUBLIC_KEY;

public abstract class Entity implements Runnable {
    protected KeyPair keyPair;

    protected final String name;
    protected final BlockingQueue<Message<?>> inbox;
    protected final MessageRouter router;

    public Entity(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        this.inbox = inbox;
        this.keyPair = CryptoTools.generateAsymmetricKeys();
        this.router = router;
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    protected void setup() {
    };

    protected abstract void handle(Message<?> msg) throws GeneralSecurityException;

    @Override
    public void run() {
        Thread.currentThread().setName(this.getClass().getSimpleName() + "-" + name);
        System.out.println("Running thread for " + this.getClass().getSimpleName() + ": " + name);
        if (!this.name.equals("TLP")) router.route(new Message<>(name, "TLP", SEND_PUBLIC_KEY, getPublicKey()));
        setup();

        try {
            while (true) {
                Message<?> msg = inbox.take();   // waits for a message
                // System.out.println(name + " Processing message from : " + msg.from());
                handle(msg);                  // process message
            }
        } catch (InterruptedException e) {
            System.out.println(name + " stopped.");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
