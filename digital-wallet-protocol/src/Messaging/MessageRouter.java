package Messaging;

import java.util.Map;
import java.util.concurrent.BlockingQueue;

public class MessageRouter {
    private final Map<String, BlockingQueue<Message<?>>> mailboxes;

    public MessageRouter(Map<String, BlockingQueue<Message<?>>> mailboxes) {
        this.mailboxes = mailboxes;
    }

    public void route(Message<?> msg) {
        BlockingQueue<Message<?>> box = mailboxes.get(msg.to());

        if (box != null) {
            System.out.println("MessageType " + msg.type() + " Sending message from " + msg.from() + " to " + msg.to());
            //System.out.println("Displaying payload:");
            //System.out.println(msg.payload());
            System.out.println("++++++++++++++++++++++++++++++++++++++++++");
            box.add(msg);
        } else {
            System.out.println("Unknown recipient: " + msg.to());
        }
    }
}
