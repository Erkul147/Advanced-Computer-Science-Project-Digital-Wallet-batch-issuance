package Helper;

import java.util.ArrayList;

public class InclusionPath {
    public ArrayList<byte[]>  hashes = new ArrayList<>();
    public ArrayList<Boolean> isSiblingLeft = new ArrayList<>();

    public void addPath(byte[] a, boolean b) {
        hashes.add(a);
        isSiblingLeft.add(b);
    }

}
