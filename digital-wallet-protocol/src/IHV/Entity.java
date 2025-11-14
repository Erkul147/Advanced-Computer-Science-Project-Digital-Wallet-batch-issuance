package IHV;

import Helper.CryptoTools;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class Entity {
    private final KeyPair keyPair;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private final String name;
    private final String type;

    public Entity(String name, String type) {
        this.keyPair = CryptoTools.generateAsymmetricKeys();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();

        this.name = name;
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

}
