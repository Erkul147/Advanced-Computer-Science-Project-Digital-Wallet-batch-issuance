package Messaging;

import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class MessageRouter implements Runnable {
    private final Map<String, BlockingQueue<Message<?>>> mailboxes;
    private BlockingQueue<Message<?>> messages = new LinkedBlockingQueue<>();

    public MessageRouter(Map<String, BlockingQueue<Message<?>>> mailboxes) {
        this.mailboxes = mailboxes;
    }

    public void route(Message<?> msg) {
        messages.add(msg);
    }

    private void handle(Message<?> msg) {
        BlockingQueue<Message<?>> box = mailboxes.get(msg.to());

        if (box != null) {
            System.out.println("MessageType " + msg.type() + " Sending message from " + msg.from() + " to " + msg.to());
            //System.out.println("Displaying payload:");
            //System.out.println(msg.payload());
            //System.out.println("++++++++++++++++++++++++++++++++++++++++++");
            box.add(msg);
        } else {
            System.out.println("Unknown recipient: " + msg.to());
        }
    }

    @Override
    public void run() {
        while (true) {
            try {
                Message<?> msg = messages.take();
                handle(msg);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
