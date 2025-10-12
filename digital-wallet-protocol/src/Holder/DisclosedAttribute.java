package Holder;

public class DisclosedAttribute {
    public byte[] salt;
    public byte[] value;

    // object to store the disclosed attribute and salt of a merkle tree
    public DisclosedAttribute(byte[] salt, byte[] value) {
        this.salt = salt;
        this.value = value;
    }
}
