package Issuer;

import java.util.Arrays;

public class Node {
    public Node parent;
    public Node[] children;
    public byte[] hash;
    public int index;
    public int height;

    public Node(byte[] hash, int height, int index, Node parent, Node[] children) {
        this.hash = hash;
        this.height = height;
        this.index = index;
        this.parent = parent;
        this.children = children;
    }

    @Override
    public String toString() {
        return "node (" + height + ", " + index + "): " + Arrays.toString(hash);
    }
}
