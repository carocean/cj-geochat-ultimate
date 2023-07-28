package cj.geochat.ability.oauth.server.entrypoint.token;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.entrypoint.app.AppAuthenticationToken;
import cj.geochat.ability.oauth.server.entrypoint.app.AuthenticationProviderUtils;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.server.generator.OAuth2TokenGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.*;

public final class OAuth2AuthorizationCodeAuthenticationProvider implements AuthenticationProvider {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE =
            new OAuth2TokenType(OAuth2ParameterNames.CODE);
    private final Log logger = LogFactory.getLog(getClass());
    private OAuth2AuthorizationService authorizationService;
    private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private SessionRegistry sessionRegistry;

    public void setAuthorizationService(OAuth2AuthorizationService authorizationService) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        this.authorizationService = authorizationService;
    }

    public void setTokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        this.tokenGenerator = tokenGenerator;
    }

    static AppAuthenticationToken getAuthenticatedAppElseThrowInvalidClient(Authentication authentication) {
        AppAuthenticationToken clientPrincipal = null;
        if (AppAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (AppAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
                (OAuth2AuthorizationCodeAuthenticationToken) authentication;

        AppAuthenticationToken clientPrincipal =
                getAuthenticatedAppElseThrowInvalidClient(authorizationCodeAuthentication);
        RegisteredApp registeredClient = clientPrincipal.getRegisteredApp();

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }
        OAuth2Authorization authorization = this.authorizationService.findByToken(
                authorizationCodeAuthentication.getCode(), AUTHORIZATION_CODE_TOKEN_TYPE);
        if (authorization == null) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved authorization with authorization code");
        }

        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);

        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
                OAuth2AuthorizationRequest.class.getName());

        if (!registeredClient.getAppId().equals(authorizationRequest.getAppId())) {
            if (!authorizationCode.isInvalidated()) {
                // Invalidate the authorization code given that a different client is attempting to use it
                authorization = AuthenticationProviderUtils.invalidate(authorization, authorizationCode.getToken());
                this.authorizationService.save(authorization);
                if (this.logger.isWarnEnabled()) {
                    this.logger.warn(LogMessage.format("Invalidated authorization code used by registered client '%s'", registeredClient.getId()));
                }
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (StringUtils.hasText(authorizationRequest.getRedirectUri()) &&
                !authorizationRequest.getRedirectUri().equals(authorizationCodeAuthentication.getRedirectUri())) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (!authorizationCode.isActive()) {
            if (authorizationCode.isInvalidated()) {
                OAuth2Token token = authorization.getRefreshToken() != null ?
                        authorization.getRefreshToken().getToken() :
                        authorization.getAccessToken().getToken();
                if (token != null) {
                    // Invalidate the access (and refresh) token as the client is attempting to use the authorization code more than once
                    authorization = AuthenticationProviderUtils.invalidate(authorization, token);
                    this.authorizationService.save(authorization);
                    if (this.logger.isWarnEnabled()) {
                        this.logger.warn(LogMessage.format("Invalidated authorization token(s) previously issued to registered client '%s'", registeredClient.getId()));
                    }
                }
            }
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated token request parameters");
        }

        Authentication principal = authorization.getAttribute(Principal.class.getName());

        // @formatter:off
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(principal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorization(authorization)
                .authorizedScopes(authorization.getAuthorizedScopes())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationCodeAuthentication);
        // @formatter:on

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);

        // ----- Access token -----
        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        authorizationBuilder.accessToken(accessToken);

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                // Do not issue refresh token to public client
                !clientPrincipal.getAppAuthenticationMethod().equals(AppAuthenticationMethod.NONE)) {

            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Generated refresh token");
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }



        authorization = authorizationBuilder.build();

        // Invalidate the authorization code as it can only be used once
        authorization = AuthenticationProviderUtils.invalidate(authorization, authorizationCode.getToken());

        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        Map<String, Object> additionalParameters = Collections.emptyMap();


        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated token request");
        }

        return new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Sets the {@link SessionRegistry} used to track OpenID Connect sessions.
     *
     * @param sessionRegistry the {@link SessionRegistry} used to track OpenID Connect sessions
     * @since 1.1
     */
    public void setSessionRegistry(SessionRegistry sessionRegistry) {
        Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
        this.sessionRegistry = sessionRegistry;
    }

    private SessionInformation getSessionInformation(Authentication principal) {
        SessionInformation sessionInformation = null;
        if (this.sessionRegistry != null) {
            List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(principal.getPrincipal(), false);
            if (!CollectionUtils.isEmpty(sessions)) {
                sessionInformation = sessions.get(0);
                if (sessions.size() > 1) {
                    // Get the most recent session
                    sessions = new ArrayList<>(sessions);
                    sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
                    sessionInformation = sessions.get(sessions.size() - 1);
                }
            }
        }
        return sessionInformation;
    }

    private static String createHash(String value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

}
