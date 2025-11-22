package Messaging.MessagingDataObjects;

import java.security.cert.X509Certificate;

public record RevokeAttestationData(String issuerName, X509Certificate attestationCertificate, String attestationID) {
}
