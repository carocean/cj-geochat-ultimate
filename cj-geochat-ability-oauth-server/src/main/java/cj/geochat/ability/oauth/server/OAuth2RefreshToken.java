package cj.geochat.ability.oauth.server;

import java.time.Instant;

public class OAuth2RefreshToken extends AbstractOAuth2Token {
    public OAuth2RefreshToken(String tokenValue, Instant issuedAt) {
        this(tokenValue, issuedAt, (Instant)null);
    }

    public OAuth2RefreshToken(String tokenValue, Instant issuedAt, Instant expiresAt) {
        super(tokenValue, issuedAt, expiresAt);
    }
}
