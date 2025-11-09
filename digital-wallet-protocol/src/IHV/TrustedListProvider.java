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

    private static List<TrustedList> trustedEntries = new ArrayList<>();
    private static TrustedList trustedList;

    public void addTrustedEntity(TrustedEntity entity) {
        if (entity == null || entity.getId() == null) {
            throw new IllegalArgumentException("Entity or Entity ID cannot be null");
        }

        String listID = UUID.randomUUID().toString();
        trustedList = new TrustedList(listID, entity.getentityType(), entity);
        trustedEntries.add(trustedList);
    }

    public void exportTrustedListToJson(String filename) {
        JSONArray jsonArray = new JSONArray();

        for (TrustedList entry : trustedEntries) {
            TrustedEntity entity = entry.getTrustedEntity();

            JSONObject trustedEntityJson = new JSONObject();
            trustedEntityJson.put("id", entity.getId());
            trustedEntityJson.put("name", entity.getName());
            trustedEntityJson.put("entityType", entity.getentityType());
            trustedEntityJson.put("issuedDate", entity.getissuedDate());
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

            JSONObject obj = new JSONObject();
            obj.put("ID", entry.getID());
            obj.put("entityType", entry.getEntityType());
            obj.put("trustedEntity", trustedEntityJson);

            jsonArray.put(obj);
        }

        try (FileWriter filer = new FileWriter(filename)) {
            filer.write(jsonArray.toString(4)); // Pretty print
            System.out.println("Trusted list exported to " + filename);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static List<TrustedList> getTrustedEntries() {
        return trustedEntries;
    }

    public static TrustedList getTrustedList() {
        return trustedList;
    }

}
