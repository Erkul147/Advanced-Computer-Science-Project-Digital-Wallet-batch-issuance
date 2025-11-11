package DataObjects;

import CommitmentSchemes.MerkleTree;

public class DisclosedAttribute {
    public byte[] salt;
    public byte[] value;
    public InclusionPath inclusionPath;

    // object to store the disclosed attribute and salt of a merkle tree
    public DisclosedAttribute(MerkleTree tree, int index) {
        this.salt = tree.salts[index];
        this.value = tree.attributes[index].getBytes();
        inclusionPath = tree.generateInclusionPath(index);
    }
}
