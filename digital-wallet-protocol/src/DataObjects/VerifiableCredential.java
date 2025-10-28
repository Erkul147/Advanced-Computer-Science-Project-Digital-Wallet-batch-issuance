package DataObjects;

import CommitmentSchemes.MerkleTree;

public class VerifiableCredential {
    public String credentialType;
    public MetaData metaData;
    public MerkleTree merkleTree;
    public byte[] signedRoot;


    // verifiable credential
    public VerifiableCredential(String proofName, MetaData metaData, MerkleTree merkleTree, byte[] signedRoot) {
        this.credentialType = proofName;
        this.metaData = metaData;
        this.merkleTree = merkleTree;
        this.signedRoot = signedRoot;
    }

}
