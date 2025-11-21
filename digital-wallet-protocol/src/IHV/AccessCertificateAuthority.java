package IHV;

import java.security.PublicKey;

import Helper.Helper;
import Messaging.Message;
import Messaging.MessageRouter;
import Messaging.MessagingDataObjects.RegistrationData;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;

import static Messaging.MessageType.CERT_ISSUED;
import static Messaging.MessageType.NOTIFY_TL;


public class AccessCertificateAuthority extends Entity {

    // asymmetrical keypair specific to an issuer
    public X509Certificate CACertificate;

    public AccessCertificateAuthority(BlockingQueue<Message<?>> inbox, MessageRouter router) {
        super("ACA", inbox, router);
    }

    @Override
    protected void handle(Message<?> msg) {
        if (msg == null) return;
        switch (msg.type()) {
            case CERT_ISSUED -> {
                if (msg.from().equals("Registrar") && msg.payload() instanceof X509Certificate cert) {
                    CACertificate = cert;
                }
            }
            case REQUEST_CERT ->  {
                if (msg.from().equals("Registrar") && msg.payload() instanceof RegistrationData payload) {
                    var certificate = createAccessCertificate("SHA256withRSA", payload.entityName(), payload.attestationType(), payload.attributes(), payload.publicKey());
                    router.route(new Message<>(name, payload.entityName(), CERT_ISSUED, certificate));
                    router.route(new Message<>(name, "TLP" , NOTIFY_TL, certificate));


                }
            }


        }

    }
    public X509Certificate createAccessCertificate(String sigAlg, String entityName, String attestationType, String[] attributesRequired, PublicKey publicKey) {
        System.out.println("        ACA: Creating Access Certificate for " + attestationType + " with " + Arrays.toString(attributesRequired) + " as attributes.");
        X500Principal subject = new X500Principal(
                "CN=" + entityName + ",OU=" + attestationType + ",O=ProjectDemo"
        );

        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                CACertificate.getSubjectX500Principal(),
                Helper.calculateSerialNumber(),
                Helper.calculateDate(0),
                Helper.calculateDate(24 * 365),
                subject,
                publicKey);

        try {
            certBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage,true, new KeyUsage(KeyUsage.digitalSignature));

            ASN1ObjectIdentifier myOID = new ASN1ObjectIdentifier("1.3.6.1.4.1.1");

            byte[] attestationTypeBytes = attestationType.getBytes();
            certBldr.addExtension(myOID, false, new DEROctetString(attestationTypeBytes));

            ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                    .setProvider("BC").build(keyPair.getPrivate());

            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

            return converter.getCertificate(certBldr.build(signer));
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new RuntimeException(e);
        }

    }

}
