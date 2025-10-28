package DataObjects;

public class VerifiablePresentation {

    public DisclosedAttribute disclosedAttribute;
    public InclusionPath path;
    public byte[] signedRoot;
    public String issuer;
    public MetaData md;

    // verifiable presentation
    public VerifiablePresentation(MetaData md, DisclosedAttribute disclosedAttribute, InclusionPath path, byte[] signedRoot, String issuer) {
        this.md = md;
        this.disclosedAttribute = disclosedAttribute;
        this.path = path;
        this.signedRoot = signedRoot;
        this.issuer = issuer;
    }
}
