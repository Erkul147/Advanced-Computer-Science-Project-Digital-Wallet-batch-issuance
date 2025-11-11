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

import Helper.CryptoTools;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import Helper.Helper;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import javax.security.auth.x500.X500Principal;


public class Registrar {
    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair = CryptoTools.generateAsymmetricKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();

    private final X509Certificate certificate;
    private final AccessCertificateAuthority ACA;

    public Registrar() {
        try {
            System.out.println("Creating trust anchor for Registrar");
            certificate = createTrustAnchor(keyPair);
        } catch (CertificateException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }

        // create Access Certificate Authority (ACA): 1. Create keypair; Create CA certificate with the keypair; 3. Instantiate a new ACA
        System.out.println("Creating keypair and CA certificate for Access Certificate Authority");
        KeyPair ACAKeyPair = CryptoTools.generateAsymmetricKeys();
        X509Certificate CACertificate = createCACertificate(certificate, ACAKeyPair.getPublic());
        ACA = new AccessCertificateAuthority(ACAKeyPair, CACertificate);

        System.out.println("Adding ACA to the trusted list");
        TrustedListProvider.ACA = ACA;
    }

    /*
    PUBLIC DATA:
    For a Relying Party, the Registrar mainly registers which attributes the Relying Party intends to request from Wallet Units, and for what purpose.
    The Registrar also registers if the Relying Party intends to use the services of an intermediary (see Section 3.11) to interact with Wallet Units, and if so, which one.
     */

    public X509Certificate registerVerifier(PublicKey publicKey, String verifierName, String attestationType, String[] attributesRequired) {

        // check if their reason is good
        return ACA.createAccessCertificate("SHA256withRSA", publicKey, verifierName, attestationType, attributesRequired);
    }


    /*
        For a PID Provider, QEAA Provider, PuB-EAA Provider, or non-qualified EAA Provider,
        the Registrar registers the attestation type(s) this entity wants to issue to Wallet Units, for example, diplomas, driving licenses or vehicle registration cards.
     */
    public X509Certificate registerIssuer(Issuer issuer, String attestationType, String[] attributesRequired) {

        // check that attestation type and the attributes they wish to request are valid, that their reason for
        // using those attributes for that attestation is ok and good.

        // if everything works, create and end entity certificate and sign with the CA key.
        // this will link the issuers public key with the certificate
        var accessCertificate = ACA.createAccessCertificate("SHA256withRSA", issuer.publicKey, issuer.name, attestationType, attributesRequired);
        TrustedListProvider.addTrustedIssuer(attestationType, issuer, accessCertificate);

        return accessCertificate;
    }

    /*
    createCACertificate:
    When an entity registers, an access certificate is given to them, which is also saved in a trusted list

    "Access Certificate Authorities are notified by a Member State to the Commission.
    As part of the notification process, the trust anchors of the Access CA are included in a Trusted List by a Trusted List Provider"
    */
    private X509Certificate createCACertificate(
            X509Certificate signerCert, PublicKey certKey)

    {
        X500Principal subject = new X500Principal("CN=Certificate Authority");


        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                Helper.calculateSerialNumber(), // id
                Helper.calculateDate(0), // valid from now
                Helper.calculateDate(24 * 365), // valid for 365 days
                subject,
                certKey);


        try {

            certBldr.addExtension(Extension.basicConstraints,true, new BasicConstraints(0))
                    .addExtension(Extension.keyUsage,true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));


            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                    .setProvider("BC").build(privateKey);


            JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


            return converter.getCertificate(certBldr.build(signer));
        } catch (CertificateException | OperatorCreationException | CertIOException e) {
            throw new RuntimeException(e);
        }
    }


    private X509Certificate createTrustAnchor(
            KeyPair keyPair)
            throws OperatorCreationException, CertificateException
    {
        X500Name name = new X500Name("CN=Trust Anchor");

        // using x509 v1 certificate as a trust anchor, it is self-signed and must be trusted at face value
        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                Helper.calculateSerialNumber(),
                Helper.calculateDate(0),
                Helper.calculateDate(24 * 365),
                name,
                keyPair.getPublic());

        // self-signing: using own private key to sign certificate that has own public key
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(keyPair.getPrivate());


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }

}


