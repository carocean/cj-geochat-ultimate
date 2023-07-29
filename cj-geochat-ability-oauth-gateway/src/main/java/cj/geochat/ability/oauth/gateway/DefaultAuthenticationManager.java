package cj.geochat.ability.oauth.gateway;

import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

/**
 * @author zlt
 * @date 2019/10/6
 * <p>
 * Blog: https://zlt2000.gitee.io
 * Github: https://github.com/zlt2000
 */
public class DefaultAuthenticationManager implements ReactiveAuthenticationManager {
    private AuthorizationService authorizationService;

    public DefaultAuthenticationManager(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        return Mono.justOrEmpty(authentication)
                .filter(a -> a instanceof BearerTokenAuthenticationToken)
                .cast(BearerTokenAuthenticationToken.class)
                .map(BearerTokenAuthenticationToken::getToken)
                .flatMap((accessTokenValue -> {
                    Authentication result = null;
                    try {
                        result = authorizationService.findByToken(accessTokenValue, authentication.getDetails());
                    } catch (Throwable e) {
                        throw new OAuth2AuthenticationException(e.getMessage());
                    }
                    if (result == null) {
                        return Mono.error(new InvalidTokenException("Invalid access token: " + accessTokenValue));
                    }
                    return Mono.just(result);
                }))
                .cast(Authentication.class);
    }
}
