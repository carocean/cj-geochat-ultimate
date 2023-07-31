package cj.geochat.ability.oauth.server;

public class AppRegistrationException extends RuntimeException {
    public AppRegistrationException(String msg) {
        super(msg);
    }

    public AppRegistrationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
