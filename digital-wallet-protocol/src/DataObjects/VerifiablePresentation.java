package DataObjects;

import CommitmentSchemes.Node;

import java.security.cert.X509Certificate;

public class VerifiablePresentation {

    public DisclosedAttribute disclosedAttribute;
    public InclusionPath path;
    public Node root;
    public byte[] signedRoot;
    public String issuer;
    public MetaData md;
    public X509Certificate providerCertificate;
    // verifiable presentation
    public VerifiablePresentation(MetaData md, DisclosedAttribute disclosedAttribute, InclusionPath path, Node root, byte[] signedRoot, String issuer, X509Certificate providerCertificate) {
        this.md = md;
        this.disclosedAttribute = disclosedAttribute;
        this.path = path;
        this.root = root;
        this.signedRoot = signedRoot;
        this.issuer = issuer;
        this.providerCertificate = providerCertificate;
    }
}
