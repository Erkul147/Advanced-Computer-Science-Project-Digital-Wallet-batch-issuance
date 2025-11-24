package IHV;

import Helper.CryptoTools;
import Helper.TrustedService;
import DataObjects.VerifiablePresentation;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.HashMap;

public class Verifier {

    // RootsVerified acts as a database or a collection that store roots that are verified.
    // Will store every root from all verifiers. This is for unlinkability data.
    public static HashMap<byte[], Integer> rootsVerified = new HashMap<>();


}
