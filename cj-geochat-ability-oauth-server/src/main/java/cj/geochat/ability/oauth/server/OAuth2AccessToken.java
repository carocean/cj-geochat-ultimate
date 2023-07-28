package cj.geochat.ability.oauth.server;

import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;

public class OAuth2AccessToken extends AbstractOAuth2Token {
    private final TokenType tokenType;
    private final Set<String> scopes;

    public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt) {
        this(tokenType, tokenValue, issuedAt, expiresAt, Collections.emptySet());
    }

    public OAuth2AccessToken(TokenType tokenType, String tokenValue, Instant issuedAt, Instant expiresAt, Set<String> scopes) {
        super(tokenValue, issuedAt, expiresAt);
        Assert.notNull(tokenType, "tokenType cannot be null");
        this.tokenType = tokenType;
        this.scopes = Collections.unmodifiableSet(scopes != null ? scopes : Collections.emptySet());
    }

    public TokenType getTokenType() {
        return this.tokenType;
    }

    public Set<String> getScopes() {
        return this.scopes;
    }

    public static final class TokenType implements Serializable {
        private static final long serialVersionUID = 610L;
        public static final TokenType BEARER = new TokenType("Bearer");
        private final String value;

        private TokenType(String value) {
            Assert.hasText(value, "value cannot be empty");
            this.value = value;
        }

        public String getValue() {
            return this.value;
        }

        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            } else if (obj != null && this.getClass() == obj.getClass()) {
                TokenType that = (TokenType)obj;
                return this.getValue().equalsIgnoreCase(that.getValue());
            } else {
                return false;
            }
        }

        public int hashCode() {
            return this.getValue().hashCode();
        }
    }
}
