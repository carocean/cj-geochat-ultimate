package cj.geochat.ability.oauth.server.entrypoint.token;

import cj.geochat.ability.oauth.server.AuthorizationGrantType;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Map;

public class OAuth2AuthorizationCodeAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String code;
    private final String redirectUri;

    /**
     * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
     *
     * @param code the authorization code
     * @param clientPrincipal the authenticated client principal
     * @param redirectUri the redirect uri
     * @param additionalParameters the additional parameters
     */
    public OAuth2AuthorizationCodeAuthenticationToken(String code, Authentication clientPrincipal,
                                                      @Nullable String redirectUri, @Nullable Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.AUTHORIZATION_CODE, clientPrincipal, additionalParameters);
        Assert.hasText(code, "code cannot be empty");
        this.code = code;
        this.redirectUri = redirectUri;
    }

    /**
     * Returns the authorization code.
     *
     * @return the authorization code
     */
    public String getCode() {
        return this.code;
    }

    /**
     * Returns the redirect uri.
     *
     * @return the redirect uri
     */
    @Nullable
    public String getRedirectUri() {
        return this.redirectUri;
    }
}
