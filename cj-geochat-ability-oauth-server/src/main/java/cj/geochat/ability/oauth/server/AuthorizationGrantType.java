package cj.geochat.ability.oauth.server;

import org.springframework.util.Assert;

import java.io.Serializable;

public final class AuthorizationGrantType implements Serializable {
    private static final long serialVersionUID = 610L;
    public static final AuthorizationGrantType AUTHORIZATION_CODE = new AuthorizationGrantType("authorization_code");
    public static final AuthorizationGrantType REFRESH_TOKEN = new AuthorizationGrantType("refresh_token");
    private final String value;

    public AuthorizationGrantType(String value) {
        Assert.hasText(value, "value cannot be empty");
        this.value = value;
    }

    public String getValue() {
        return this.value;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (obj != null && this.getClass() == obj.getClass()) {
            AuthorizationGrantType that = (AuthorizationGrantType)obj;
            return this.getValue().equals(that.getValue());
        } else {
            return false;
        }
    }

    public int hashCode() {
        return this.getValue().hashCode();
    }
}
