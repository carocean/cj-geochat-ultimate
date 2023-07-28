package cj.geochat.ability.oauth.server.entrypoint.authorize.consent;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationToken;
import cj.geochat.ability.oauth.server.repository.RegisteredAppRepository;
import cj.geochat.ability.oauth.server.generator.OAuth2AuthorizationCodeGenerator;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationConsentService;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.server.generator.OAuth2TokenGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Authorization Consent
 * used in the Authorization Code Grant.
 *
 * @author Joe Grandja
 * @see OAuth2AuthorizationConsentAuthenticationToken
 * @see OAuth2AuthorizationConsent
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider
 * @see RegisteredAppRepository
 * @see OAuth2AuthorizationService
 * @see OAuth2AuthorizationConsentService
 * @since 0.4.0
 */
public final class OAuth2AuthorizationConsentAuthenticationProvider implements AuthenticationProvider {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);
    private final Log logger = LogFactory.getLog(getClass());
    private  RegisteredAppRepository registeredAppRepository;
    private  OAuth2AuthorizationService authorizationService;
    private  OAuth2AuthorizationConsentService authorizationConsentService;
    private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();
    private Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication =
                (OAuth2AuthorizationConsentAuthenticationToken) authentication;

        OAuth2Authorization authorization = this.authorizationService.findByToken(
                authorizationConsentAuthentication.getState(), STATE_TOKEN_TYPE);
        if (authorization == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
                    authorizationConsentAuthentication, null, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved authorization with authorization consent state");
        }

        // The 'in-flight' authorization must be associated to the current principal
        Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
        if (!isPrincipalAuthenticated(principal) || !principal.getName().equals(authorization.getPrincipalName())) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE,
                    authorizationConsentAuthentication, null, null);
        }

        RegisteredApp registeredClient = this.registeredAppRepository.findByAppId(
                authorizationConsentAuthentication.getAppId());
        if (registeredClient == null || !registeredClient.getId().equals(authorization.getRegisteredAppId())) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.APP_ID,
                    authorizationConsentAuthentication, registeredClient, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(OAuth2AuthorizationRequest.class.getName());
        Set<String> requestedScopes = authorizationRequest.getScopes();
        Set<String> authorizedScopes = new HashSet<>(authorizationConsentAuthentication.getScopes());
        if (!requestedScopes.containsAll(authorizedScopes)) {
            throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
                    authorizationConsentAuthentication, registeredClient, authorizationRequest);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated authorization consent request parameters");
        }

        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
                authorization.getRegisteredAppId(), authorization.getPrincipalName());
        Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
                currentAuthorizationConsent.getScopes() : Collections.emptySet();

        if (!currentAuthorizedScopes.isEmpty()) {
            for (String requestedScope : requestedScopes) {
                if (currentAuthorizedScopes.contains(requestedScope)) {
                    authorizedScopes.add(requestedScope);
                }
            }
        }


        OAuth2AuthorizationConsent.Builder authorizationConsentBuilder;
        if (currentAuthorizationConsent != null) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Retrieved existing authorization consent");
            }
            authorizationConsentBuilder = OAuth2AuthorizationConsent.from(currentAuthorizationConsent);
        } else {
            authorizationConsentBuilder = OAuth2AuthorizationConsent.withId(
                    authorization.getRegisteredAppId(), authorization.getPrincipalName());
        }
        authorizedScopes.forEach(authorizationConsentBuilder::scope);

        if (this.authorizationConsentCustomizer != null) {
            // @formatter:off
			OAuth2AuthorizationConsentAuthenticationContext authorizationConsentAuthenticationContext =
					OAuth2AuthorizationConsentAuthenticationContext.with(authorizationConsentAuthentication)
							.authorizationConsent(authorizationConsentBuilder)
							.registeredClient(registeredClient)
							.authorization(authorization)
							.authorizationRequest(authorizationRequest)
							.build();
			// @formatter:on
            this.authorizationConsentCustomizer.accept(authorizationConsentAuthenticationContext);
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Customized authorization consent");
            }
        }

        Set<GrantedAuthority> authorities = new HashSet<>();
        authorizationConsentBuilder.authorities(authorities::addAll);

        if (authorities.isEmpty()) {
            // Authorization consent denied (or revoked)
            if (currentAuthorizationConsent != null) {
                this.authorizationConsentService.remove(currentAuthorizationConsent);
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Revoked authorization consent");
                }
            }
            this.authorizationService.remove(authorization);
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Removed authorization");
            }
            throwError(OAuth2ErrorCodes.ACCESS_DENIED, OAuth2ParameterNames.APP_ID,
                    authorizationConsentAuthentication, registeredClient, authorizationRequest);
        }

        OAuth2AuthorizationConsent authorizationConsent = authorizationConsentBuilder.build();
        if (!authorizationConsent.equals(currentAuthorizationConsent)) {
            this.authorizationConsentService.save(authorizationConsent);
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Saved authorization consent");
            }
        }

        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
                authorizationConsentAuthentication, registeredClient, authorization, authorizedScopes);
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the authorization code.", ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated authorization code");
        }

        OAuth2Authorization updatedAuthorization = OAuth2Authorization.from(authorization)
                .authorizedScopes(authorizedScopes)
                .token(authorizationCode)
                .attributes(attrs -> {
                    attrs.remove(OAuth2ParameterNames.STATE);
                })
                .build();
        this.authorizationService.save(updatedAuthorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        String redirectUri = authorizationRequest.getRedirectUri();
        if (!StringUtils.hasText(redirectUri)) {
            redirectUri = registeredClient.getRedirectUris().iterator().next();
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated authorization consent request");
        }

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(
                authorizationRequest.getAuthorizationUri(), registeredClient.getAppId(), principal, authorizationCode,
                redirectUri, authorizationRequest.getState(), authorizedScopes);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationConsentAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setAuthorizationConsentService(OAuth2AuthorizationConsentService authorizationConsentService) {
        this.authorizationConsentService = authorizationConsentService;
    }

    public void setRegisteredAppRepository(RegisteredAppRepository registeredAppRepository) {
        this.registeredAppRepository = registeredAppRepository;
    }

    public void setAuthorizationService(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    /**
     * Sets the {@link OAuth2TokenGenerator} that generates the {@link OAuth2AuthorizationCode}.
     *
     * @param authorizationCodeGenerator the {@link OAuth2TokenGenerator} that generates the {@link OAuth2AuthorizationCode}
     */
    public void setAuthorizationCodeGenerator(OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
        Assert.notNull(authorizationCodeGenerator, "authorizationCodeGenerator cannot be null");
        this.authorizationCodeGenerator = authorizationCodeGenerator;
    }

    /**
     * Sets the {@code Consumer} providing access to the {@link OAuth2AuthorizationConsentAuthenticationContext}
     * containing an {@link OAuth2AuthorizationConsent.Builder} and additional context information.
     *
     * <p>
     * The following context attributes are available:
     * <ul>
     * <li>The {@link OAuth2AuthorizationConsent.Builder} used to build the authorization consent
     * prior to {@link OAuth2AuthorizationConsentService#save(OAuth2AuthorizationConsent)}.</li>
     * <li>The {@link Authentication} of type
     * {@link OAuth2AuthorizationConsentAuthenticationToken}.</li>
     * <li>The {@link RegisteredApp} associated with the authorization request.</li>
     * <li>The {@link OAuth2Authorization} associated with the state token presented in the
     * authorization consent request.</li>
     * <li>The {@link OAuth2AuthorizationRequest} associated with the authorization consent request.</li>
     * </ul>
     *
     * @param authorizationConsentCustomizer the {@code Consumer} providing access to the
     *                                       {@link OAuth2AuthorizationConsentAuthenticationContext} containing an {@link OAuth2AuthorizationConsent.Builder}
     */
    public void setAuthorizationConsentCustomizer(Consumer<OAuth2AuthorizationConsentAuthenticationContext> authorizationConsentCustomizer) {
        Assert.notNull(authorizationConsentCustomizer, "authorizationConsentCustomizer cannot be null");
        this.authorizationConsentCustomizer = authorizationConsentCustomizer;
    }

    private static OAuth2TokenContext createAuthorizationCodeTokenContext(
            OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication,
            RegisteredApp registeredAPP, OAuth2Authorization authorization, Set<String> authorizedScopes) {

        // @formatter:off
		return DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredAPP)
				.principal((Authentication) authorizationConsentAuthentication.getPrincipal())
				.authorization(authorization)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrant(authorizationConsentAuthentication)
				.build();
		// @formatter:on
    }

    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null &&
                !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
                principal.isAuthenticated();
    }

    private static void throwError(String errorCode, String parameterName,
                                   OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication,
                                   RegisteredApp registeredAPP, OAuth2AuthorizationRequest authorizationRequest) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
        throwError(error, parameterName, authorizationConsentAuthentication, registeredAPP, authorizationRequest);
    }

    private static void throwError(OAuth2Error error, String parameterName,
                                   OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication,
                                   RegisteredApp registeredAPP, OAuth2AuthorizationRequest authorizationRequest) {

        String redirectUri = resolveRedirectUri(authorizationRequest, registeredAPP);
        if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST) &&
                (parameterName.equals(OAuth2ParameterNames.APP_ID) ||
                        parameterName.equals(OAuth2ParameterNames.STATE))) {
            redirectUri = null;        // Prevent redirects
        }

        String state = authorizationRequest != null ?
                authorizationRequest.getState() :
                authorizationConsentAuthentication.getState();
        Set<String> requestedScopes = authorizationRequest != null ?
                authorizationRequest.getScopes() :
                authorizationConsentAuthentication.getScopes();

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        authorizationConsentAuthentication.getAuthorizationUri(), authorizationConsentAuthentication.getAppId(),
                        (Authentication) authorizationConsentAuthentication.getPrincipal(), redirectUri,
                        state, requestedScopes, null);

        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
    }

    private static String resolveRedirectUri(OAuth2AuthorizationRequest authorizationRequest, RegisteredApp registeredClient) {
        if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
            return authorizationRequest.getRedirectUri();
        }
        if (registeredClient != null) {
            return registeredClient.getRedirectUris().iterator().next();
        }
        return null;
    }

}
