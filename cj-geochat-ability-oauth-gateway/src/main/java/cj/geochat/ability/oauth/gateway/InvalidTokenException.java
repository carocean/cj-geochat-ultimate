package cj.geochat.ability.oauth.gateway;

import org.springframework.security.core.AuthenticationException;

public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException(String msg, Throwable t) {
        super(msg, t);
    }

    public InvalidTokenException(String msg) {
        super(msg);
    }

    public int getHttpErrorCode() {
        return 401;
    }

    public String getOAuth2ErrorCode() {
        return "invalid_token";
    }
}