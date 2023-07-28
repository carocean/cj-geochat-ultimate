package cj.geochat.ability.oauth.server.generator;

import cj.geochat.ability.oauth.server.OAuth2AccessToken;
import cj.geochat.ability.oauth.server.OAuth2AuthorizationCode;
import cj.geochat.ability.oauth.server.OAuth2TokenContext;
import cj.geochat.ability.oauth.server.OAuth2TokenType;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import com.github.f4b6a3.ulid.UlidCreator;
import org.springframework.lang.Nullable;

import java.time.Instant;

/**
 * An {@link OAuth2TokenGenerator} that generates an {@link OAuth2AuthorizationCode}.
 *
 * @author Joe Grandja
 * @see OAuth2TokenGenerator
 * @see OAuth2AuthorizationCode
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * // * @see OAuth2AuthorizationConsentAuthenticationProvider
 * @since 0.4.0
 */
public final class OAuth2AccessTokenGenerator implements OAuth2TokenGenerator<OAuth2AccessToken> {

    @Nullable
    @Override
    public OAuth2AccessToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredApp().getAuthorizationAccessTokenTimeToLive());
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, UlidCreator.getUlid().toLowerCase(), issuedAt, expiresAt, context.getAuthorizedScopes());
    }

}
