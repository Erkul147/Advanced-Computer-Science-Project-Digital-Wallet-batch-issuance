package DataObjects;

import IHV.Issuer;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;

public record TrustedIssuerData(String name, HashMap<String, X509Certificate> certificateMap) {


}
