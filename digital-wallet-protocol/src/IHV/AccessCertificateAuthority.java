package IHV;

import java.security.KeyPair;
import java.security.PublicKey;

import Helper.Helper;
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


public class AccessCertificateAuthority {

    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair;
    public X509Certificate CACertificate;

    public AccessCertificateAuthority(KeyPair keyPair, X509Certificate CACertificate) {
        this.keyPair = keyPair;
        this.CACertificate = CACertificate;
    }

    public X509Certificate createAccessCertificate(String sigAlg, PublicKey certKey, String name, String attestationType, String[] attributesRequired) {
        System.out.println("        ACA: Creating Access Certificate for " + attestationType + " with " + Arrays.toString(attributesRequired) + " as attributes.");
        X500Principal subject = new X500Principal(
                "CN=" + name + ",OU=Issuer,O=ProjectDemo"
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

            ASN1ObjectIdentifier myOID = new ASN1ObjectIdentifier("1.3.6.1.4.1.1");

            byte[] attestationTypeBytes = attestationType.getBytes();
            certBldr.addExtension(myOID, false, new DEROctetString(attestationTypeBytes));

            ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                    .setProvider("BC").build(keyPair.getPrivate());


            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");

            X509Certificate cert = converter.getCertificate(certBldr.build(signer));

            return cert;
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new RuntimeException(e);
        }

    }

    private void NotifyTrustedListProvider(String attestationType, Issuer issuer, X509Certificate cert) {
        TrustedListProvider.addTrustedIssuer(attestationType, issuer, cert);
    }


}
