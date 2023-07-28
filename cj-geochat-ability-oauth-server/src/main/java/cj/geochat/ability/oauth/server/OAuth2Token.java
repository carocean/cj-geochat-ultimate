package cj.geochat.ability.oauth.server;

import org.springframework.lang.Nullable;

import java.time.Instant;

public interface OAuth2Token {
    String getTokenValue();

    @Nullable
    default Instant getIssuedAt() {
        return null;
    }

    @Nullable
    default Instant getExpiresAt() {
        return null;
    }
}
