package DataObjects;

import CommitmentSchemes.Node;

import java.security.cert.X509Certificate;

public record VerifiablePresentation(MetaData md, DisclosedAttribute[] disclosedAttributes, Node root,
                                     byte[] signedRoot, String issuer, X509Certificate providerCertificate) {

    // verifiable presentation
}
