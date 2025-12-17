package IHV;

import DataObjects.DisclosedAttribute;
import DataObjects.VerifiablePresentation;
import DataObjects.VerifierDataCollection;
import Helper.CryptoTools;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.BlockingQueue;


public class MalignVerifier extends Verifier {
    public static HashMap<String, Integer> rootMap = new HashMap<>();
    public static HashMap<String, Integer> seenIDsMap = new HashMap<>();

    public MalignVerifier(String name, BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super(name, inbox, router);
    }

    @Override
    public void handle(Message<?> msg) {
        super.handle(msg);

        if (Objects.requireNonNull(msg.type()) != MessageType.PRESENT_PRESENTATION) return;
        if (!(msg.payload() instanceof VerifiablePresentation VP)) return;

        DisclosedAttribute[] DAs = VP.disclosedAttributes();
        for (DisclosedAttribute disclosedAttribute : DAs) {
            if (!Objects.equals(disclosedAttribute.attributeName, "ID")) continue;

            var ID = new String(disclosedAttribute.value, StandardCharsets.UTF_8);
            seenIDsMap.putIfAbsent(ID, 0); // if ID not seen, add 0.
            seenIDsMap.put(ID, seenIDsMap.get(ID) + 1);

            String root = CryptoTools.printHash(VP.root().hash);
            rootMap.putIfAbsent(root, 0);
            rootMap.put(root, rootMap.get(root) + 1);
        }

    }


    public void checkUnlinkability() {
        var msg = (Issuer.batchIssuance) ? "\nBATCH ISSUANCE WAS ENABLED" : "\nBATCH ISSUANCE WAS DISABLED";


        msg += "\nTotal amount of holders verified: " + rootMap.size();
        StringBuilder msgAfter = new StringBuilder();
        int totalTransactions = 0;
        for (Map.Entry<String, Integer> entry : seenIDsMap.entrySet()) {
            String key = entry.getKey();
            Integer value = entry.getValue();
            totalTransactions += value;
            msgAfter.append("\n").append(key).append(" has been seen ").append(value).append(" times.");
        }

        msg += "\nDuplicate roots: " + (rootMap.size() != totalTransactions);
        msg += msgAfter.toString();
        System.out.println(msg);
    }
}
