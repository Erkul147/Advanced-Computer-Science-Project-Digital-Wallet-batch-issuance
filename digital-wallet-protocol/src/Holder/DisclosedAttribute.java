package Holder;

public class DisclosedAttribute<T> {
    public byte[] salt;
    public byte[] value;

    public DisclosedAttribute(byte[] salt, byte[] value) {
        this.salt = salt;
        this.value = value;
    }
}
