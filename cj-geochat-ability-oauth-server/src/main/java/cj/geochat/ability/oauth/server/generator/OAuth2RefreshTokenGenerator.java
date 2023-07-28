package cj.geochat.ability.oauth.server.generator;

import cj.geochat.ability.oauth.server.OAuth2RefreshToken;
import cj.geochat.ability.oauth.server.OAuth2TokenContext;
import cj.geochat.ability.oauth.server.OAuth2TokenType;
import com.github.f4b6a3.ulid.UlidCreator;
import org.springframework.lang.Nullable;

import java.time.Instant;

public final class OAuth2RefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {
//    private final StringKeyGenerator refreshTokenGenerator =
//            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    @Nullable
    @Override
    public OAuth2RefreshToken generate(OAuth2TokenContext context) {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType())) {
            return null;
        }
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(context.getRegisteredApp().getAuthorizationRefreshTokenTimeToLive());
        return new OAuth2RefreshToken(UlidCreator.getUlid().toLowerCase(), issuedAt, expiresAt);
    }

}
