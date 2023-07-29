package cj.geochat.ability.oauth.gateway;

import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

public class OAuth2AuthenticationException extends AuthenticationException {
    private final OAuth2Error error;

    public OAuth2AuthenticationException(String errorCode) {
        this(new OAuth2Error(errorCode));
    }

    public OAuth2AuthenticationException(OAuth2Error error) {
        this(error, error.getDescription());
    }

    public OAuth2AuthenticationException(OAuth2Error error, Throwable cause) {
        this(error, cause.getMessage(), cause);
    }

    public OAuth2AuthenticationException(OAuth2Error error, String message) {
        this(error, message, (Throwable)null);
    }

    public OAuth2AuthenticationException(OAuth2Error error, String message, Throwable cause) {
        super(message, cause);
        Assert.notNull(error, "error cannot be null");
        this.error = error;
    }

    public OAuth2Error getError() {
        return this.error;
    }
}
