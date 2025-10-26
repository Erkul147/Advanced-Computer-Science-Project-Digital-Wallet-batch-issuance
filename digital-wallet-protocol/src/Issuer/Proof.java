package Issuer;

public class Proof {
    public String proofName;
    public MetaData metaData;
    public MerkleTree merkleTree;
    public byte[] signedRoot;


    public Proof(String proofName, MetaData metaData, MerkleTree merkleTree, byte[] signedRoot) {
        this.proofName = proofName;
        this.metaData = metaData;
        this.merkleTree = merkleTree;
        this.signedRoot = signedRoot;
    }

}
