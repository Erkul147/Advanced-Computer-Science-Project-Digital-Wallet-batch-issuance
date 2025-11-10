package DataObjects.TrustedListEntities;

import DataObjects.TrustedEntity;

import java.security.cert.X509Certificate;

public class PIDProvider extends TrustedEntity {
    private String levelOfAssurance; // Idk skal vi tage det med?

    public PIDProvider(String ID, String name,  String entityType, Boolean status, X509Certificate X509CertificateInfo, String levelOfAssurance) {
        super(ID, name, entityType, status, X509CertificateInfo);
        this.levelOfAssurance = levelOfAssurance;
    }
    public String getLevelOfAssurance() {return levelOfAssurance;}
}
