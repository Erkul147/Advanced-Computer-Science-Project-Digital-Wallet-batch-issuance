package Holder;

import Helper.InclusionPath;
import Issuer.Issuer;

public class PresentationProof {

    public DisclosedAttribute disclosedAttribute;
    public InclusionPath path;
    public byte[] signedRoot;
    public Issuer issuer; // maybe just the name of the issuer, the verifier can find the information themselves

    public PresentationProof(DisclosedAttribute disclosedAttribute, InclusionPath path, byte[] signedRoot, Issuer issuer) {
        this.disclosedAttribute = disclosedAttribute;
        this.path = path;
        this.signedRoot = signedRoot;
        this.issuer = issuer;
    }
}
