package DataObjects;

import CommitmentSchemes.MerkleTree;

import java.security.cert.X509Certificate;

public class VerifiableCredential {
    public String credentialType;
    public MetaData metaData;
    public MerkleTree merkleTree;
    public byte[] signedRoot;
    public X509Certificate providerCertificate;


    // verifiable credential
    public VerifiableCredential(String proofName, MetaData metaData, MerkleTree merkleTree, byte[] signedRoot, X509Certificate providerCertificate) {
        this.credentialType = proofName;
        this.metaData = metaData;
        this.merkleTree = merkleTree;
        this.signedRoot = signedRoot;
        this.providerCertificate = providerCertificate;
    }

}
