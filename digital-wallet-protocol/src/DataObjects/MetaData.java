package DataObjects;
import java.util.UUID;

import java.sql.Timestamp;;

public class MetaData {
    public final String ID = UUID.randomUUID().toString();
    public String issuingCountry;
    public String issuingAuthority;
    public String expiryDate;
    public Timestamp timestamp;
    public String signatureAlgorithm;

    public MetaData(String issuingCountry, String issuingAuthority, String expiryDate, String signatureAlgorithm) {
        this.issuingCountry = issuingCountry;
        this.issuingAuthority = issuingAuthority;
        this.expiryDate = expiryDate;
        timestamp = new Timestamp(System.currentTimeMillis());
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
