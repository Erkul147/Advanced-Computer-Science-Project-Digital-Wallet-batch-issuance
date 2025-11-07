package IHV;

import Helper.CryptoTools;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import Helper.Helper;
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


public class AccessCertificateAuthority {

    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair = CryptoTools.generateAsymmetricKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();
    public X509Certificate CACertificate;

    public AccessCertificateAuthority() {
        CACertificate = TrustedService.registrar.requestCACertificate(publicKey);
        TrustedService.registrar.ACA = this;
    }



    public X509Certificate createEndEntity(String sigAlg, PublicKey certKey, String entityName, String entityType, String attestationType, String[] attributesRequest) {

        X500Principal subject = new X500Principal(
                "CN=" + entityName + ",OU=" + entityType + ",O=ProjectDemo"
        );



        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                CACertificate.getSubjectX500Principal(),
                Helper.calculateSerialNumber(),
                Helper.calculateDate(0),
                Helper.calculateDate(24 * 365),
                subject,
                certKey);

        try {
            certBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage,true, new KeyUsage(KeyUsage.digitalSignature));


            ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                    .setProvider("BC").build(privateKey);


            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

            X509Certificate cert = converter.getCertificate(certBldr.build(signer));
            NotifyTrustedListProvider(attestationType, entityName, entityType, cert);

            return cert;
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new RuntimeException(e);
        }

    }

    private void NotifyTrustedListProvider(String attestationType, String entityName, String entityType, X509Certificate cert) {
    }


}
