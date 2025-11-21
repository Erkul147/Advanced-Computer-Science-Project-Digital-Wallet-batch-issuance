package Messaging.MessagingDataObjects;

import java.security.PublicKey;

public record RegistrationData(String entityName, String entityType, String attestationType, String[] attributes, PublicKey publicKey) {
}
