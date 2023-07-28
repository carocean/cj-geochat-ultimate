package cj.geochat.ability.oauth.server.generator;

import cj.geochat.ability.oauth.server.OAuth2AuthorizationCode;
import cj.geochat.ability.oauth.server.OAuth2ParameterNames;
import cj.geochat.ability.oauth.server.OAuth2TokenContext;
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
public final class OAuth2AuthorizationCodeGenerator implements OAuth2TokenGenerator<OAuth2AuthorizationCode> {
//	private final StringKeyGenerator authorizationCodeGenerator =
//			new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Nullable
    @Override
    public OAuth2AuthorizationCode generate(OAuth2TokenContext context) {
        if (context.getTokenType() == null ||
                !OAuth2ParameterNames.CODE.equals(context.getTokenType().getValue())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredApp().getAuthorizationCodeTimeToLive());
        return new OAuth2AuthorizationCode(UlidCreator.getUlid().toLowerCase(), issuedAt, expiresAt);
    }

}
