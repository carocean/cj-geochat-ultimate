package cj.geochat.ability.oauth.app;

import org.springframework.util.Assert;

import java.io.Serializable;

public class OAuth2Error implements Serializable {
    private static final long serialVersionUID = 610L;
    private final String errorCode;
    private final String description;
    private final String uri;

    public OAuth2Error(String errorCode) {
        this(errorCode, (String)null, (String)null);
    }

    public OAuth2Error(String errorCode, String description, String uri) {
        Assert.hasText(errorCode, "errorCode cannot be empty");
        this.errorCode = errorCode;
        this.description = description;
        this.uri = uri;
    }

    public final String getErrorCode() {
        return this.errorCode;
    }

    public final String getDescription() {
        return this.description;
    }

    public final String getUri() {
        return this.uri;
    }

    public String toString() {
        String var10000 = this.getErrorCode();
        return "[" + var10000 + "] " + (this.getDescription() != null ? this.getDescription() : "");
    }
}
