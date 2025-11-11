package DataObjects;

import java.sql.Timestamp;

public record MetaData(String ID, String issuerName, String issuingCountry, String[] type, String expiryDate,
                       String attestationType, Timestamp timestamp, String signatureAlgorithm) {
}
