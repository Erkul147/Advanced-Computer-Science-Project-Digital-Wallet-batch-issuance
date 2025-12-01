package DataObjects;

import java.util.ArrayList;

public class AuthenticationSteps {
    public ArrayList<Integer> indexes = new ArrayList<>();
    public ArrayList<String> attributes = new  ArrayList<>();
    public ArrayList<byte[]> salts = new  ArrayList<>();
    public byte[][] hashes;

    public AuthenticationSteps(byte[][] hashes) {
        this.hashes = hashes;
    }

    public void addAuthenticationSteps(int index, String attribute, byte[] salt) {
        indexes.add(Integer.valueOf(index));
        attributes.add(attribute);
        salts.add(salt);
    }
}