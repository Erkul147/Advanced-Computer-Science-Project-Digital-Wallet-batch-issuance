package DataObjects;

import CommitmentSchemes.MerkleTree;
import IHV.Issuer;

import java.security.cert.X509Certificate;

public record VerifiableCredential(String credentialType, MetaData metaData, MerkleTree merkleTree, byte[] signedRoot,
                                   Issuer issuer, X509Certificate providerCertificate) {
    // verifiable credential

}
