package cj.geochat.ability.oauth.gateway;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Collections;

public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 610L;
    private final String token;

    public BearerTokenAuthenticationToken(String token) {
        super(Collections.emptyList());
        Assert.hasText(token, "token cannot be empty");
        this.token = token;
    }

    public String getToken() {
        return this.token;
    }

    public Object getCredentials() {
        return this.getToken();
    }

    public Object getPrincipal() {
        return this.getToken();
    }
}