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


import java.math.BigInteger;
import java.security.PublicKey;

import java.security.*;

import Helper.CryptoTools;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v1CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v1CertificateBuilder;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;

import javax.security.auth.x500.X500Principal;


    /*
        Certificate steps:
            Create registrar with Public - Private keys
            Entity (RP or Provider) generates key pair and create CSR
            Regristar verifies CSR and signs it
            Entity can then use that signed CSR for signing or authentication
            Other people can use registrars public key to verify signature
     */

public class Registrar {
    // asymmetrical keypair specific to an issuer
    private final KeyPair keyPair = CryptoTools.generateAsymmetricKeys();
    private final PrivateKey privateKey = keyPair.getPrivate();
    public final PublicKey publicKey = keyPair.getPublic();
    private static long serialNumberBase = System.currentTimeMillis();

        private X509Certificate certificate;


    public Registrar() {
        try {
            certificate = createTrustAnchor(keyPair);
        } catch (CertificateException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    /*
        IssueAccessCertificate:
        When an entity registers, an access certificate is given to them, which is also saved in a trusted list

        "[when AC is issued] Access Certificate Authorities are notified by a Member State to the Commission.
        As part of the notification process, the trust anchors of the Access CA are included in a Trusted List by a Trusted List Provider"
     */
    public void IssueAccessCertificate(PublicKey publicKey, String attestationType, String issuer) {
        // X.509 v3 certificate: https://learn.microsoft.com/en-us/azure/iot-hub/reference-x509-certificates
        // https://www.bouncycastle.org/ from openssl recommendation for self-signed certificates
        // https://doc.primekey.com/bouncycastle/how-to-guides-pki-at-the-edge/how-to-generate-key-pairs-and-certification-requests


    }

    public static X509Certificate createCACertificate(
            X509Certificate signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey, int followingCACerts)
            throws GeneralSecurityException,
            OperatorCreationException, CertIOException
    {
        X500Principal subject = new X500Principal("CN=Certificate Authority");


        X509v3CertificateBuilder certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 60),
                subject,
                certKey);


        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();


        certBldr.addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(followingCACerts))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.keyCertSign
                                | KeyUsage.cRLSign));


        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }

    public static X509Certificate createEndEntity(
            X509Certificate signerCert, PrivateKey signerKey,
            String sigAlg, PublicKey certKey)
            throws CertIOException, OperatorCreationException, CertificateException
    {
        X500Principal subject = new X500Principal("CN=End Entity");


        X509v3CertificateBuilder  certBldr = new JcaX509v3CertificateBuilder(
                signerCert.getSubjectX500Principal(),
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 31),
                subject,
                certKey);


        certBldr.addExtension(Extension.basicConstraints,
                        true, new BasicConstraints(false))
                .addExtension(Extension.keyUsage,
                        true, new KeyUsage(KeyUsage.digitalSignature));


        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(signerKey);


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }


    public static X509Certificate createTrustAnchor(
            KeyPair keyPair)
            throws OperatorCreationException, CertificateException
    {
        X500Name name = new X500Name("CN=Trust Anchor");
        System.out.println(org.bouncycastle.operator.jcajce.JcaContentSignerBuilder.class.getProtectionDomain().getCodeSource().getLocation());


        X509v1CertificateBuilder certBldr = new JcaX509v1CertificateBuilder(
                name,
                calculateSerialNumber(),
                calculateDate(0),
                calculateDate(24 * 365),
                name,
                keyPair.getPublic());


        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC").build(keyPair.getPrivate());


        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider("BC");


        return converter.getCertificate(certBldr.build(signer));
    }

    public void NotifyTrustedListProvider() {

    }

    // helpers
    public static Date calculateDate(int hoursInFuture)
    {
        long secs = System.currentTimeMillis() / 1000;


        return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
    }
    public static synchronized BigInteger calculateSerialNumber()
    {
        return BigInteger.valueOf(serialNumberBase++);
    }







}


