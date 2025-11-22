package IHV;

/*
    https://eudi.dev/2.6.0/architecture-and-reference-framework-main/#317-registrars
    Registrar - where issuers and RPs registrates:
                    1 PID Providers,
                    2 QEAA Providers,
                    3 PuB-EAA Providers,
                    4 non-qualified EAA Providers and
                    5 Relying Parties
                    in the EUDI Wallet ecosystem are registered by a Registrar in the Member State where they reside.


    1-4. PID Provider, QEAA Provider, PuB-EAA Provider, or non-qualified EAA Provider:
        1. For a PID Provider, QEAA Provider, PuB-EAA Provider, or non-qualified EAA Provider,
        the Registrar registers the attestation type(s) this entity wants to issue to Wallet Units, for example,
                diplomas, driving licenses or vehicle registration cards.

    5. RPs:
        1. For a Relying Party, the Registrar mainly registers which attributes the Relying Party intends to request from Wallet Units, and for what purpose.
        2. The Registrar also registers if the Relying Party intends to use the services of an intermediary (see Section 3.11) to interact with Wallet Units, and if so, which one.
 */


import java.security.PublicKey;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;

import Helper.Helper;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessagingDataObjects.RegistrationData;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import javax.security.auth.x500.X500Principal;

import static Messaging.MessageType.*;


public class Registrar extends Entity {

    private X509Certificate certificate;

    public Registrar(BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super("Registrar", inbox, router);

    }

    @Override
    protected void handle(Message<?> msg) {
        if (msg == null) return;
        switch (msg.type()) {

            case START -> {
                System.out.println("Creating trust anchor for Registrar");
                certificate = createTrustAnchor();
                router.route(new Message<>(getName(), "TLP", NOTIFY_TL_TA, certificate));

                router.route(new Message<>(getName(), "TLP", REQUEST_PUBLIC_KEY, "ACA"));
            }

            case RESPONSE_PUBLIC_KEY -> {
                if (msg.payload() instanceof PublicKey pk && msg.from().equals("TLP")) {
                    var ca = createCACertificate(pk);
                    router.route(new Message<>(name, "ACA", CERT_ISSUED, ca));
                    router.route(new Message<>(name, "TLP", NOTIFY_TL_CA, ca));
                }
            }

            case REQUEST_REGISTRATION -> {
                if (msg.payload() instanceof RegistrationData payload) {
                    router.route(new Message<>(name, "ACA", REQUEST_CERT, payload));
                }
            }



        }
    }

    private X509Certificate createCACertificate(PublicKey certKey) {
        X500Principal subject = new X500Principal("CN=Certificate Authority, O=ProjectDemo");

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                certificate.getSubjectX500Principal(),
                Helper.calculateSerialNumber(), // id
                Helper.calculateDate(0), // valid from now
                Helper.calculateDate(24 * 365), // valid for 365 days
                subject,
                certKey);

        X509Certificate cert;

        try {
            certBldr.addExtension(Extension.basicConstraints,true, new BasicConstraints(0))
                    .addExtension(Extension.keyUsage,true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(getPrivateKey());

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

            cert = converter.getCertificate(certBldr.build(signer));
        } catch (CertificateException | OperatorCreationException | CertIOException e) {
            throw new RuntimeException(e);
        }

        return cert;
    }


    private X509Certificate createTrustAnchor() {

        X500Principal subject = new X500Principal("CN=Trust Anchor, O=ProjectDemo");
        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                subject, // issuer
                Helper.calculateSerialNumber(),
                Helper.calculateDate(0),
                Helper.calculateDate(24 * 365),
                subject, // subject
                getPublicKey()
        );
        X509Certificate cert;
        try {
            // This marks it as a ROOT CA
            certBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certBldr.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC").build(getPrivateKey());

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
                    .setProvider("BC");

            cert = converter.getCertificate(certBldr.build(signer));
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new RuntimeException(e);
        }

        return cert;

    }

}


