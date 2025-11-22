package IHV;

import Helper.CryptoTools;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.BlockingQueue;

public abstract class Entity implements Runnable{
    protected KeyPair keyPair;

    protected final String name;
    protected final BlockingQueue<Message<?>> inbox;
    protected final MessageRouter router;

    public Entity(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        this.inbox = inbox;
        this.keyPair = CryptoTools.generateAsymmetricKeys();
        this.router = router;
        this.name = name;
        router.route(new Message<>(name, "TLP", MessageType.RESPONSE_PUBLIC_KEY, getPublicKey()));

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

    protected abstract void handle(Message<?> msg) throws GeneralSecurityException;

    @Override
    public void run() {
        try {
            while (true) {
                // System.out.println(name + " inbox messages: " + inbox.size());
                Message<?> msg = inbox.take();   // waits for a message
                handle(msg);                  // process message
            }
        } catch (InterruptedException e) {
            System.out.println(name + " stopped.");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
