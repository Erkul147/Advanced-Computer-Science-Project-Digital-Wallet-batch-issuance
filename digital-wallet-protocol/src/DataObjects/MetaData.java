package DataObjects;
import java.util.UUID;

import java.sql.Timestamp;;

public class MetaData {
    public final String ID = UUID.randomUUID().toString();
    public String issuerName;
    public String issuingCountry;
    public String[] type;
    public String expiryDate;
    public Timestamp timestamp;
    public String signatureAlgorithm;

    public MetaData(String issuerName, String issuingCountry, String[] type, String expiryDate, String signatureAlgorithm) {
        this.issuerName = issuerName;
        this.issuingCountry = issuingCountry;
        this.type = type;
        this.expiryDate = expiryDate;
        timestamp = new Timestamp(System.currentTimeMillis());
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
