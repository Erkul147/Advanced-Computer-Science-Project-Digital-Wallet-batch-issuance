package DataObjects;

import IHV.Issuer;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;

public record TrustedIssuerData(String ID, Issuer issuer, String name, PublicKey publicKey, HashMap<String, X509Certificate> certificateMap) {


}
