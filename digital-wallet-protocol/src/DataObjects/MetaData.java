package DataObjects;
import java.util.UUID;

import java.sql.Timestamp;;

public class MetaData {
    public final String ID = UUID.randomUUID().toString();
    public final String issuerName;
    public final String issuingCountry;
    public final String[] type;
    public final String expiryDate;
    public final String attestationType;
    public final Timestamp timestamp;
    public final String signatureAlgorithm;

    public MetaData(String issuerName, String issuingCountry, String[] type, String expiryDate, String attestationType, String signatureAlgorithm) {
        this.issuerName = issuerName;
        this.issuingCountry = issuingCountry;
        this.type = type;
        this.expiryDate = expiryDate;
        this.attestationType = attestationType;
        this.timestamp = new Timestamp(System.currentTimeMillis());
        this.signatureAlgorithm = signatureAlgorithm;
    }
}
