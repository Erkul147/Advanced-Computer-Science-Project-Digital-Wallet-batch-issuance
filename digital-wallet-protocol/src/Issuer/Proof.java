package Issuer;

public class Proof {
    MerkleTree merkleTree;
    String signedRoot;


    public Proof(MerkleTree merkleTree, String signedRoot) {
        this.merkleTree = merkleTree;
        this.signedRoot = signedRoot;
    }

    public void generateProof(int index) {
        // ...
    }

}
