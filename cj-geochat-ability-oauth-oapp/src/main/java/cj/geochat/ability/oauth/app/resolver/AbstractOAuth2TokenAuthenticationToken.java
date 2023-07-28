package cj.geochat.ability.oauth.app.resolver;

import cj.geochat.ability.oauth.app.OAuth2Token;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Map;

public abstract class AbstractOAuth2TokenAuthenticationToken<T extends OAuth2Token> extends AbstractAuthenticationToken {
    private static final long serialVersionUID = 610L;
    private Object principal;
    private Object credentials;
    private T token;

    protected AbstractOAuth2TokenAuthenticationToken(T token) {
        this(token, (Collection)null);
    }

    protected AbstractOAuth2TokenAuthenticationToken(T token, Collection<? extends GrantedAuthority> authorities) {
        this(token, token, token, authorities);
    }

    protected AbstractOAuth2TokenAuthenticationToken(T token, Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        Assert.notNull(token, "token cannot be null");
        Assert.notNull(principal, "principal cannot be null");
        this.principal = principal;
        this.credentials = credentials;
        this.token = token;
    }

    public Object getPrincipal() {
        return this.principal;
    }

    public Object getCredentials() {
        return this.credentials;
    }

    public final T getToken() {
        return this.token;
    }

    public abstract Map<String, Object> getTokenAttributes();
}
