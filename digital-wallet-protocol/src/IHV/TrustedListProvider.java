package IHV;

import DataObjects.*;

import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.*;

import DataObjects.TrustedListEntities.ACAProvider;
import DataObjects.TrustedListEntities.PIDProvider;
import DataObjects.TrustedListEntities.QEAAProvider;
import org.json.*;


public class TrustedListProvider {

    private static HashMap<String, TrustedEntity> trustedEntities = new HashMap<>();
    public static Registrar  registrar;
    public static AccessCertificateAuthority ACA;

    public static void addTrustedEntity(String attestationType, String entityName, String entityType, X509Certificate cert) {
        String ID = cert.getSerialNumber().toString();

        switch (entityType.toLowerCase()) {
            case "issuer":
            case "pidprovider":
                PIDProvider pid = new PIDProvider(
                        ID, entityName, "PID Provider", true, cert, "high"
                );
                trustedEntities.put(ID, pid);
                break;

            case "qeaa":
                QEAAProvider qeaa = new QEAAProvider(
                        ID, entityName, "QEAA Provider", true, cert, attestationType
                );
                trustedEntities.put(ID, qeaa);
                break;

            case "aca":
                ACAProvider aca = new ACAProvider(
                        ID, entityName, "ACA Provider",
                        true, cert, attestationType
                );
                trustedEntities.put(ID, aca);
                break;

            default:
                System.out.println("Unknown entity type: " + entityType);
        }

        exportTrustedListToJson("digital-wallet-protocol/src/trustedList.json");
    }


    public static TrustedEntity getTrustedtrustedEntity(String ID) {
        return trustedEntities.get(ID);
    }

    public static void getCertificateOfAnEntity(String ID) {


    }

    public static void exportTrustedListToJson(String filename) {
        JSONArray jsonArray = new JSONArray();

        for (TrustedEntity entity : trustedEntities.values()) {
            JSONObject trustedEntityJson = new JSONObject();
            trustedEntityJson.put("id", entity.getID());
            trustedEntityJson.put("name", entity.getName());
            trustedEntityJson.put("entityType", entity.getentityType());
            trustedEntityJson.put("status", entity.getStatus());

            if (entity.getX509CertificateInfo() != null) {
                X509Certificate cert = entity.getX509CertificateInfo();
                JSONObject certJson = new JSONObject();
                certJson.put("version", cert.getVersion());
                certJson.put("issuer", cert.getIssuerX500Principal().getName());
                certJson.put("subject", cert.getSubjectX500Principal().getName());
                certJson.put("serialNumber", cert.getSerialNumber().toString());
                certJson.put("validFrom", cert.getNotBefore().toString());
                certJson.put("validTo", cert.getNotAfter().toString());
                certJson.put("algorithm", cert.getSigAlgName());
                certJson.put("publicKeyFormat", cert.getPublicKey().getFormat());
                certJson.put("publicKeyAlgorithm", cert.getPublicKey().getAlgorithm());
                certJson.put("publicKey", cert.getPublicKey().toString());
                trustedEntityJson.put("x509certificate", certJson);
            } else {
                trustedEntityJson.put("x509certificate", JSONObject.NULL);
            }

            // Add subclass-specific fields
            if (entity instanceof PIDProvider pid) {
                trustedEntityJson.put("levelOfAssurance", pid.getLevelOfAssurance());
            } else if (entity instanceof QEAAProvider qeaa) {
                trustedEntityJson.put("attestationType", qeaa.getAttestationType());
            } else if (entity instanceof ACAProvider aca) {
                trustedEntityJson.put("attestationType", aca.getAttestationType());
            }

            jsonArray.put(trustedEntityJson);
        }

        try (FileWriter filer = new FileWriter(filename)) {
            filer.write(jsonArray.toString(4)); // Pretty print
            System.out.println("Trusted list exported to " + filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
