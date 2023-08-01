package cj.geochat.ability.oauth.app.principal;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.Principal;
import java.util.Collection;

public class DefaultAppAuthentication implements Authentication {
    DefaultAppPrincipal principal;

    boolean isAuthenticated;
    DefaultAppAuthenticationDetails details;

    public DefaultAppAuthentication(DefaultAppPrincipal principal, DefaultAppAuthenticationDetails details) {
        this.principal = principal;
        this.details = details;
        isAuthenticated=true;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return principal.getAuthorities();
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    @Override
    public String getName() {
        return principal == null ? "" : principal.getName();
    }
}
