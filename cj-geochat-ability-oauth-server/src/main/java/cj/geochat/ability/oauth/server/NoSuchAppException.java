package cj.geochat.ability.oauth.server;

public class NoSuchAppException extends AppRegistrationException {
    public NoSuchAppException(String msg) {
        super(msg);
    }

    public NoSuchAppException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
