package cj.geochat.ability.oauth.server;

import org.springframework.util.Assert;

import java.io.Serializable;

public final class OAuth2AuthorizationResponseType implements Serializable {
    private static final long serialVersionUID = 610L;
    public static final OAuth2AuthorizationResponseType CODE = new OAuth2AuthorizationResponseType("code");
    private final String value;

    public OAuth2AuthorizationResponseType(String value) {
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
            OAuth2AuthorizationResponseType that = (OAuth2AuthorizationResponseType)obj;
            return this.getValue().equals(that.getValue());
        } else {
            return false;
        }
    }

    public int hashCode() {
        return this.getValue().hashCode();
    }
}
