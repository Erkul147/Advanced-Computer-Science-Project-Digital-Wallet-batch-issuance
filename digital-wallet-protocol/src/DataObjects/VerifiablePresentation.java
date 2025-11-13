package DataObjects;

import CommitmentSchemes.Node;
import Helper.CryptoTools;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;

public record VerifiablePresentation(MetaData md, DisclosedAttribute[] disclosedAttributes, Node root,
                                     byte[] signedRoot, String issuer, X509Certificate providerCertificate) {

    // verifiable presentation

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("VerifiablePresentation\n");
        sb.append("  Metadata\n");
        sb.append("    ID: ").append(md.ID()).append("\n");
        sb.append("    Issuer: ").append(md.issuerName()).append("\n");
        sb.append("    Country: ").append(md.issuingCountry()).append("\n");
        sb.append("    Type: ").append(md.attestationType()).append("\n");
        sb.append("    Timestamp: ").append(md.timestamp()).append("\n");
        sb.append("    Expiry: ").append(md.expiryDate()).append("\n");
        sb.append("    SignatureAlgorithm: ").append(md.signatureAlgorithm()).append("\n\n");


        sb.append("  Disclosed Attributes:\n");
        for (DisclosedAttribute da : disclosedAttributes) {
            sb.append("    - ").append(da.toString()).append("\n");
        }
        sb.append("\n");

        sb.append("  Issuer Certificate\n");
        if (providerCertificate != null) {
            sb.append("    Subject: ").append(providerCertificate.getSubjectX500Principal()).append("\n");
            sb.append("    Issuer:  ").append(providerCertificate.getIssuerX500Principal()).append("\n");
            sb.append("    Valid:   ")
                    .append(providerCertificate.getNotBefore()).append(" -> ")
                    .append(providerCertificate.getNotAfter()).append("\n");
            sb.append("    Public Key Fingerprint (SHA-256): ")
                    .append(fingerprint(providerCertificate)).append("\n");
        } else {
            sb.append("    <no provider certificate>\n");
        }

        sb.append("  Merkle Proof\n");
        sb.append("    Root: ").append(CryptoTools.printHash(root.hash)).append("\n");
        sb.append("    Signed Root: ").append(CryptoTools.printHash(signedRoot)).append("\n\n");


        return sb.toString();
    }

    private static String fingerprint(X509Certificate cert) {
        try {
            byte[] encoded = cert.getPublicKey().getEncoded();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(encoded);

            StringBuilder hex = new StringBuilder();
            for (byte b : digest) hex.append(String.format("%02X:", b));
            return hex.substring(0, hex.length() - 1);
        } catch (Exception e) {
            return "<error generating fingerprint>";
        }
    }
}
