package cj.geochat.ability.oauth.iapp.entrypoint;

import cj.geochat.ability.oauth.iapp.principal.DefaultAppAuthentication;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public final class InsideAppAuthenticationProvider implements AuthenticationProvider {


    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof DefaultAppAuthentication bearer)) {
            return null;
        }
        bearer.setAuthenticated(true);
        return authentication;
    }

    public boolean supports(Class<?> authentication) {
        return DefaultAppAuthentication.class.isAssignableFrom(authentication);
    }


}
