package cj.geochat.ability.oauth.app.entrypoint;

import cj.geochat.ability.oauth.app.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.app.resolver.BearerTokenAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public final class OpaqueTokenAuthenticationProvider implements AuthenticationProvider {
    private final Log logger = LogFactory.getLog(this.getClass());
    private final OAuth2AuthorizationService authorizationService;

    public OpaqueTokenAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof BearerTokenAuthenticationToken bearer)) {
            return null;
        }
        Authentication result= null;
        try {
            result = authorizationService.findByToken(bearer.getToken(),authentication.getDetails());
        } catch (Throwable e) {
            throw new RuntimeException(e);
        }
        if (result == null) {
            return null;
        } else {
            if (AbstractAuthenticationToken.class.isAssignableFrom(result.getClass())) {
                AbstractAuthenticationToken auth = (AbstractAuthenticationToken)result;
                if (auth.getDetails() == null) {
                    auth.setDetails(bearer.getDetails());
                }
            }

            this.logger.debug("Authenticated token");
            return result;
        }
    }

    public boolean supports(Class<?> authentication) {
        return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }


}
