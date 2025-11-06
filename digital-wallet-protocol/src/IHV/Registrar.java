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


import java.nio.channels.SeekableByteChannel;
import java.security.PublicKey;

import java.security.*;

import Helper.CryptoTools;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;


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

    // using bouncy castle, and adding it as the provider
    static {
        Security.addProvider(new BouncyCastleProvider());
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


    public void NotifyTrustedListProvider() {

    }





}


