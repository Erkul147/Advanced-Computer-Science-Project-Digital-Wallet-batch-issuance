package DataObjects;

import CommitmentSchemes.MerkleTree;
import Helper.CryptoTools;

public class DisclosedAttribute {
    public byte[] salt;
    public byte[] value;
    public String attributeName;
    public InclusionPath inclusionPath;

    // object to store the disclosed attribute and salt of a merkle tree
    // also stores the inclusion path
    public DisclosedAttribute(MerkleTree tree, int index, String attributeName) {
        this.salt = tree.salts[index];
        this.value = tree.attributes[index].getBytes();
        this.attributeName = attributeName;
        inclusionPath = tree.generateInclusionPath(index);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append(" DisclosedAttribute {\n");

        sb.append("    attribute: \"")
                .append(attributeName)
                .append("\"\n");

        sb.append("    value: \"")
                .append(new String(value))
                .append("\"\n");

        sb.append("    salt: ")
                .append(CryptoTools.printHash(salt))
                .append("\n");

        sb.append("    Merkle Tree inclusionPath: [\n");

        for (int i = 0; i < inclusionPath.hashes.size(); i++) {
            String hash = CryptoTools.printHash(inclusionPath.hashes.get(i));
            boolean isLeft = inclusionPath.isSiblingLeft.get(i);

            sb.append("      { hash: ")
                    .append(hash)
                    .append("   , leftSibling: ")
                    .append(isLeft)
                    .append("    }\n");
        }

        sb.append("        ]\n");
        sb.append("      }");

        return sb.toString();
    }
}
