package Issuer;

public class Proof {
    public String proofName;
    public MerkleTree merkleTree;
    public byte[] signedRoot;
    public Issuer issuer;


    public Proof(String proofName, MerkleTree merkleTree, byte[] signedRoot, Issuer issuer) {
        this.proofName = proofName;
        this.merkleTree = merkleTree;
        this.signedRoot = signedRoot;
        this.issuer = issuer;
    }

}
