package DataObjects;

import java.security.cert.X509Certificate;

public abstract class TrustedEntity {
    public String ID;
    public String name;
    public String entityType;
    public String issuedDate;
    public Boolean status;
    public X509Certificate X509CertificateInfo;


    public TrustedEntity(String ID, String name, String entityType, String issuedDate, Boolean status, X509Certificate X509CertificateInfo) {
        this.ID = ID;
        this.name = name;
        this.entityType = entityType;
        this.issuedDate = issuedDate;
        this.status = status;
        this.X509CertificateInfo = X509CertificateInfo;
    }

    public String getId() { return ID; }
    public String getName() { return name; }
    public String getentityType() { return entityType; }
    public String getissuedDate() { return issuedDate; }
    public Boolean getStatus() { return status; }
    public void setStatus(Boolean status) { this.status = status; }
    public X509Certificate getX509CertificateInfo() { return X509CertificateInfo; }
}
