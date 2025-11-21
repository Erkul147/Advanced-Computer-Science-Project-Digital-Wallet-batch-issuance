package IHV;

import DataObjects.*;

import java.io.FileWriter;
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.BlockingQueue;

import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;
import org.json.*;



public class TrustedListProvider extends Entity {

    private static final HashMap<String, PublicKey> publicKeys = new HashMap<>();
    private static final HashMap<String, TrustedIssuerData> trustedIssuers = new HashMap<>();
    public static List<String> revocationList = new ArrayList<>();
    private static X509Certificate CACertificate;


    public static Registrar  registrar;
    public static AccessCertificateAuthority ACA;

    public TrustedListProvider(BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super("TLP", inbox, router);
    }

    @Override
    protected void handle(Message<?> msg) {
        System.out.println("\nhanlding message\n");
        if (msg == null) return;
        switch (msg.type()) {
            case RESPONSE_PUBLIC_KEY -> {
                System.out.println("Received public key from " + msg.from());
                if (msg.payload() != null && msg.payload() instanceof PublicKey key) {
                    publicKeys.put(msg.from(), key);
                    System.out.println("Public key received and added to list: " + msg.from());
                }
            }
            case REQUEST_PUBLIC_KEY -> {
                PublicKey key = publicKeys.get(msg.from());
                System.out.println("Public key requested");
                if (key == null) router.route(new Message<>("TLP", msg.from(), MessageType.ERROR, "No public key found for: " + msg.from()));

                router.route(new Message<>("TLP", msg.from(), MessageType.RESPONSE_PUBLIC_KEY, key));
            }
        }
    }

    public static void addTrustedIssuer(String attestationType, Issuer issuer, X509Certificate cert) {

        // if issuer does not exist, create it and initialize an attestation map
        boolean issuerExists = trustedIssuers.get(issuer.getName()) != null;

        if (!issuerExists) {
            String ID = cert.getSerialNumber().toString();
            TrustedIssuerData trustedIssuer = new TrustedIssuerData(ID, issuer, issuer.getName(), cert.getPublicKey(), new HashMap<>());
            trustedIssuers.put(issuer.getName(), trustedIssuer);
        }

        // add attestation to issuer's attestation map
        trustedIssuers.get(issuer.getName()).certificateMap().put(attestationType, cert);

        exportTrustedListToJson("digital-wallet-protocol/src/trustedList.json");
    }


    public static TrustedIssuerData getTrustedIssuer(String name) {
        return trustedIssuers.get(name);
    }

    public static boolean addRevocation(String attestationNo) {
        if (revocationList.contains(attestationNo)) {
            System.out.println("Revocation already exists");
            return false;
        }
        System.out.println("Revocation added - "  + attestationNo);
        revocationList.add(attestationNo);
        return true;
    }

    public static X509Certificate getCACertificate() {
        return CACertificate;
    }

    public static void setCACertificate(X509Certificate CACertificate) {
        TrustedListProvider.CACertificate = CACertificate;
    }
    public static boolean isProofRevoked(String attestationNo) {
        var isRevoked = revocationList.contains(attestationNo);
        if (isRevoked) System.out.println("Proof not valid: revoked - " + attestationNo);
        return isRevoked;
    }
    public static void exportTrustedListToJson(String filename) {
        JSONArray jsonArray = new JSONArray();

        for (TrustedIssuerData issuer : trustedIssuers.values()) {
            JSONObject trustedEntityJson = new JSONObject();
            trustedEntityJson.put("id", issuer.ID());
            trustedEntityJson.put("name", issuer.name());


            for (String attestationType: issuer.certificateMap().keySet()) {
                var certificate =  issuer.certificateMap().get(attestationType);

                JSONObject certJson = new JSONObject();
                certJson.put("version", certificate.getVersion());
                certJson.put("issuer", certificate.getIssuerX500Principal().getName());
                certJson.put("subject", certificate.getSubjectX500Principal().getName());
                certJson.put("serialNumber", certificate.getSerialNumber().toString());
                certJson.put("attestationType", attestationType);
                certJson.put("validFrom", certificate.getNotBefore().toString());
                certJson.put("validTo", certificate.getNotAfter().toString());
                certJson.put("algorithm", certificate.getSigAlgName());
                certJson.put("publicKeyFormat", certificate.getPublicKey().getFormat());
                certJson.put("publicKeyAlgorithm", certificate.getPublicKey().getAlgorithm());
                certJson.put("publicKey", certificate.getPublicKey().toString());
                trustedEntityJson.put("x509certificate", certJson);
            }


            jsonArray.put(trustedEntityJson);
        }

        try (FileWriter filer = new FileWriter(filename)) {
            filer.write(jsonArray.toString(4)); // Pretty print
            //System.out.println("Trusted list exported to " + filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
