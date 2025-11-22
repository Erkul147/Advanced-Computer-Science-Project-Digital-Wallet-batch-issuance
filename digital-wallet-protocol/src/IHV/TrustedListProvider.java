package IHV;

import DataObjects.*;

import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.BlockingQueue;

import Helper.CryptoTools;
import Helper.Helper;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessageType;
import Messaging.MessagingDataObjects.RevokeAttestationData;
import org.json.*;

import static Messaging.MessageType.*;


public class TrustedListProvider extends Entity {

    private static final HashMap<String, PublicKey> publicKeys = new HashMap<>();
    private static final HashMap<String, TrustedIssuerData> trustedIssuers = new HashMap<>();
    public static List<String> revocationList = new ArrayList<>();
    private static X509Certificate CACertificate;
    private static X509Certificate trustAnchor;


    public TrustedListProvider(BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super("TLP", inbox, router);
    }

    @Override
    protected void handle(Message<?> msg) throws GeneralSecurityException {

        if (msg == null) return;
        switch (msg.type()) {
            case RESPONSE_PUBLIC_KEY -> {
                if (msg.payload() != null && msg.payload() instanceof PublicKey key) {
                    publicKeys.put(msg.from(), key);
                }
            }

            case SEND_PUBLIC_KEY -> {
                if (msg.payload() != null && msg.payload() instanceof PublicKey key) {
                    publicKeys.put(msg.from(), key);
                }
            }

            case REQUEST_PUBLIC_KEY -> {
                if (msg.payload() != null && msg.payload() instanceof String payloadName) {
                    PublicKey key = publicKeys.get(payloadName);
                    router.route(new Message<>("TLP", msg.from(), RESPONSE_PUBLIC_KEY, key));
                    break;
                }
                router.route(new Message<>("TLP", msg.from(), MessageType.ERROR, "No public key found for: " + msg.from()));

            }

            case NOTIFY_TL -> {
                if (msg.payload() != null && msg.payload() instanceof X509Certificate cert) {
                    addTrustedIssuer(cert);
                }
            }

            case NOTIFY_TL_TA -> {
                if (msg.from().equals("Registrar") && msg.payload() != null && msg.payload() instanceof X509Certificate cert) {
                    trustAnchor = cert;
                }
            }
            case NOTIFY_TL_CA -> {
                if (msg.from().equals("Registrar") && msg.payload() != null && msg.payload() instanceof X509Certificate cert) {
                    CACertificate = cert;
                }
            }

            case VERIFY_CERT -> {
                if (msg.payload() instanceof X509Certificate cert) {

                    var chain = new HashSet<X509Certificate>();
                    chain.add(trustAnchor);
                    chain.add(CACertificate);

                    PKIXCertPathBuilderResult certPath = Helper.buildAndVerifyChain(cert, chain);
                    // verified

                    System.out.println("cert good");
                    router.route(new Message<>(name, msg.from(), ATTESTATION_VERIFIED, cert));
                }

                if (msg.payload() instanceof VerifiablePresentation VP) {

                    var chain = new HashSet<X509Certificate>();
                    chain.add(trustAnchor);
                    chain.add(CACertificate);

                    PKIXCertPathBuilderResult certPath = Helper.buildAndVerifyChain(VP.providerCertificate(), chain);
                    // verified

                    var proofRevoked = isProofRevoked(VP.md().ID());
                    if (proofRevoked) {
                        router.route(new Message<>(name, msg.from(), ERROR, "Not revoked"));
                        return;
                    }

                    System.out.println("VP good");
                    router.route(new Message<>(name, msg.from(), ATTESTATION_VERIFIED, VP));
                }
            }

            case REVOKE_ATTESTATION -> {
                if (msg.payload() instanceof RevokeAttestationData payload) {

                    // chain of certificates
                    var chain = new HashSet<X509Certificate>();
                    chain.add(trustAnchor);
                    chain.add(CACertificate);
                    PKIXCertPathBuilderResult certPath = Helper.buildAndVerifyChain(payload.attestationCertificate(), chain);
                    // verified

                    addRevocation(payload.attestationID());
                }
            }
        }
    }

    public static void addTrustedIssuer(X509Certificate cert) {

        String issuerName = cert.getSubjectX500Principal().getName();
        // if issuer does not exist, create it and initialize an attestation map
        boolean issuerExists = trustedIssuers.get(issuerName) != null;

        if (!issuerExists) {
            HashMap<String, X509Certificate> certificateMap = new HashMap<>();
            TrustedIssuerData trustedIssuer = new TrustedIssuerData(issuerName, certificateMap);
            trustedIssuers.put(issuerName, trustedIssuer);
        }

        // add attestation to issuer's attestation map
        trustedIssuers.get(issuerName).certificateMap().put(CryptoTools.getAttestationFromCertificate(cert), cert);

        exportTrustedListToJson("digital-wallet-protocol/src/trustedList.json");
    }

    public static void addRevocation(String attestationNo) {
        if (revocationList.contains(attestationNo)) {
            System.out.println("Revocation already exists");
            return;
        }
        System.out.println("Revocation added - "  + attestationNo);
        revocationList.add(attestationNo);
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
