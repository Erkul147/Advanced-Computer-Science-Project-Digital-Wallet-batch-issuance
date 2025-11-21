package Messaging;

public record Message<T>(String from, String to, MessageType type, T payload) {
}
