package cj.geochat.ability.oauth.app;

import org.springframework.http.HttpStatus;

public final class BearerTokenErrors {
    private static final BearerTokenError DEFAULT_INVALID_REQUEST = invalidRequest("Invalid request");
    private static final BearerTokenError DEFAULT_INVALID_TOKEN = invalidToken("Invalid token");
    private static final BearerTokenError DEFAULT_INSUFFICIENT_SCOPE = insufficientScope("Insufficient scope", (String)null);
    private static final String DEFAULT_URI = "https://tools.ietf.org/html/rfc6750#section-3.1";

    private BearerTokenErrors() {
    }

    public static BearerTokenError invalidRequest(String message) {
        try {
            return new BearerTokenError("invalid_request", HttpStatus.BAD_REQUEST, message, "https://tools.ietf.org/html/rfc6750#section-3.1");
        } catch (IllegalArgumentException var2) {
            return DEFAULT_INVALID_REQUEST;
        }
    }

    public static BearerTokenError invalidToken(String message) {
        try {
            return new BearerTokenError("invalid_token", HttpStatus.UNAUTHORIZED, message, "https://tools.ietf.org/html/rfc6750#section-3.1");
        } catch (IllegalArgumentException var2) {
            return DEFAULT_INVALID_TOKEN;
        }
    }

    public static BearerTokenError insufficientScope(String message, String scope) {
        try {
            return new BearerTokenError("insufficient_scope", HttpStatus.FORBIDDEN, message, "https://tools.ietf.org/html/rfc6750#section-3.1", scope);
        } catch (IllegalArgumentException var3) {
            return DEFAULT_INSUFFICIENT_SCOPE;
        }
    }
}