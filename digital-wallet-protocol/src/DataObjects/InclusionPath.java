package DataObjects;

import java.util.ArrayList;

// an inclusion path contains a list of all the hashes and directions needed to create the root of a merkle tree
public class InclusionPath {
    public ArrayList<byte[]>  hashes = new ArrayList<>();
    public ArrayList<Boolean> isSiblingLeft = new ArrayList<>();

    public void addPath(byte[] a, boolean b) {
        hashes.add(a);
        isSiblingLeft.add(b);
    }

}
