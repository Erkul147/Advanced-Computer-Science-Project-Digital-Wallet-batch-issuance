package DataObjects;

import java.util.ArrayList;

public class AuthenticationSteps {
    public ArrayList<Integer> indexes = new ArrayList<>();
    public ArrayList<String> attributes = new  ArrayList<>();
    public ArrayList<byte[]> salts = new  ArrayList<>();


    public void addAuthenticationSteps(int index, String attribute, byte[] salt) {
        indexes.add(index);
        attributes.add(attribute);
        salts.add(salt);
    }
}