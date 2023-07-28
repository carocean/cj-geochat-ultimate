package cj.geochat.ability.oauth.server.entrypoint.token;

import cj.geochat.ability.oauth.server.OAuth2AccessToken;
import cj.geochat.ability.oauth.server.OAuth2RefreshToken;
import cj.geochat.ability.oauth.server.RegisteredApp;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.Map;

public class OAuth2AccessTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final RegisteredApp registeredApp;
    private final Authentication appPrincipal;
    private final OAuth2AccessToken accessToken;
    private final OAuth2RefreshToken refreshToken;
    private final Map<String, Object> additionalParameters;

    /**
     * Constructs an {@code OAuth2AccessTokenAuthenticationToken} using the provided parameters.
     *
     * @param registeredApp the registered client
     * @param appPrincipal the authenticated client principal
     * @param accessToken the access token
     */
    public OAuth2AccessTokenAuthenticationToken(RegisteredApp registeredApp,
                                                Authentication appPrincipal, OAuth2AccessToken accessToken) {
        this(registeredApp, appPrincipal, accessToken, null);
    }

    /**
     * Constructs an {@code OAuth2AccessTokenAuthenticationToken} using the provided parameters.
     *
     * @param registeredApp the registered client
     * @param appPrincipal the authenticated client principal
     * @param accessToken the access token
     * @param refreshToken the refresh token
     */
    public OAuth2AccessTokenAuthenticationToken(RegisteredApp registeredApp, Authentication appPrincipal,
                                                OAuth2AccessToken accessToken, @Nullable OAuth2RefreshToken refreshToken) {
        this(registeredApp, appPrincipal, accessToken, refreshToken, Collections.emptyMap());
    }

    /**
     * Constructs an {@code OAuth2AccessTokenAuthenticationToken} using the provided parameters.
     *
     * @param registeredApp the registered client
     * @param appPrincipal the authenticated client principal
     * @param accessToken the access token
     * @param refreshToken the refresh token
     * @param additionalParameters the additional parameters
     */
    public OAuth2AccessTokenAuthenticationToken(RegisteredApp registeredApp, Authentication appPrincipal,
                                                OAuth2AccessToken accessToken, @Nullable OAuth2RefreshToken refreshToken, Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(registeredApp, "registeredClient cannot be null");
        Assert.notNull(appPrincipal, "clientPrincipal cannot be null");
        Assert.notNull(accessToken, "accessToken cannot be null");
        Assert.notNull(additionalParameters, "additionalParameters cannot be null");
        this.registeredApp = registeredApp;
        this.appPrincipal = appPrincipal;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.additionalParameters = additionalParameters;
    }


    @Override
    public Object getPrincipal() {
        return this.appPrincipal;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    /**
     * Returns the {@link RegisteredApp registered client}.
     *
     * @return the {@link RegisteredApp}
     */
    public RegisteredApp getRegisteredApp() {
        return this.registeredApp;
    }

    /**
     * Returns the {@link OAuth2AccessToken access token}.
     *
     * @return the {@link OAuth2AccessToken}
     */
    public OAuth2AccessToken getAccessToken() {
        return this.accessToken;
    }

    /**
     * Returns the {@link OAuth2RefreshToken refresh token}.
     *
     * @return the {@link OAuth2RefreshToken} or {@code null} if not available
     */
    @Nullable
    public OAuth2RefreshToken getRefreshToken() {
        return this.refreshToken;
    }

    /**
     * Returns the additional parameters.
     *
     * @return a {@code Map} of the additional parameters, may be empty
     */
    public Map<String, Object> getAdditionalParameters() {
        return this.additionalParameters;
    }
}
