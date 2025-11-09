package DataObjects.TrustedListEntities;

import DataObjects.TrustedEntity;

import java.security.cert.X509Certificate;

public class ACAProvider extends TrustedEntity {
    private String attestationType;

    public ACAProvider(String ID, String name,  String entityType, String issedDate, Boolean status, X509Certificate X509CertificateInfo, String attestationType) {
        super(ID, name, entityType, issedDate, status, X509CertificateInfo);
        this.attestationType = attestationType;
    }
    public String getAttestationType() { return attestationType; }
}
