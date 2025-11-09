package DataObjects;

public class TrustedList {
    public String ID;
    public String entityType;
    public TrustedEntity trustedEntity;

    public TrustedList(String ID, String entityType, TrustedEntity trustedEntity) {
        this.ID = ID;
        this.entityType = entityType;
        this.trustedEntity = trustedEntity;
    }

    public String getID() { return ID; }
    public String getEntityType() { return entityType; }
    public TrustedEntity getTrustedEntity() { return trustedEntity; }

}
