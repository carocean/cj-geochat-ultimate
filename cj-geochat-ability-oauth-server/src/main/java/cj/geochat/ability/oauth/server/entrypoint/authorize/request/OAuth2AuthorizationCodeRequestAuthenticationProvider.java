package cj.geochat.ability.oauth.server.entrypoint.authorize.request;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.entrypoint.authorize.consent.OAuth2AuthorizationConsentAuthenticationToken;
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
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.util.Base64;
import java.util.Set;

public class OAuth2AuthorizationCodeRequestAuthenticationProvider implements AuthenticationProvider {
    private final Log logger = LogFactory.getLog(getClass());
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

    private static final StringKeyGenerator DEFAULT_STATE_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder());
    private RegisteredAppRepository registeredAppRepository;
    private OAuth2AuthorizationService authorizationService;
    private OAuth2AuthorizationConsentService authorizationConsentService;
    private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator = new OAuth2AuthorizationCodeGenerator();

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        RegisteredApp registeredApp = this.registeredAppRepository.findByAppId(
                authorizationCodeRequestAuthentication.getAppId());
        if (registeredApp == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.APP_ID,
                    authorizationCodeRequestAuthentication, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }


        if (!registeredApp.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
            throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.APP_ID,
                    authorizationCodeRequestAuthentication, registeredApp);
        }



        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Validated authorization code request parameters");
        }

        // ---------------
        // The request is valid - ensure the resource owner is authenticated
        // ---------------

        Authentication principal = (Authentication) authorizationCodeRequestAuthentication.getPrincipal();
        if (!isPrincipalAuthenticated(principal)) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Did not authenticate authorization code request since principal not authenticated");
            }
            // Return the authorization request as-is where isAuthenticated() is false
            return authorizationCodeRequestAuthentication;
        }

        OAuth2AuthorizationRequest authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(authorizationCodeRequestAuthentication.getAuthorizationUri())
                .clientId(registeredApp.getAppId())
                .redirectUri(authorizationCodeRequestAuthentication.getRedirectUri())
                .scopes(authorizationCodeRequestAuthentication.getScopes())
                .state(authorizationCodeRequestAuthentication.getState())
                .additionalParameters(authorizationCodeRequestAuthentication.getAdditionalParameters())
                .build();

        OAuth2AuthorizationConsent currentAuthorizationConsent = this.authorizationConsentService.findById(
                registeredApp.getId(), principal.getName());

        if (requireAuthorizationConsent(registeredApp, authorizationRequest, currentAuthorizationConsent)) {
            String state =StringUtils.hasText(authorizationRequest.getState())? authorizationRequest.getState():DEFAULT_STATE_GENERATOR.generateKey();
            OAuth2Authorization authorization = authorizationBuilder(registeredApp, principal, authorizationRequest)
                    .attribute(OAuth2ParameterNames.STATE, state)
                    .build();

            if (this.logger.isTraceEnabled()) {
                logger.trace("Generated authorization consent state");
            }

            this.authorizationService.save(authorization);

            Set<String> currentAuthorizedScopes = currentAuthorizationConsent != null ?
                    currentAuthorizationConsent.getScopes() : null;

            if (this.logger.isTraceEnabled()) {
                this.logger.trace("Saved authorization");
            }

            return new OAuth2AuthorizationConsentAuthenticationToken(authorizationRequest.getAuthorizationUri(),
                    registeredApp.getAppId(), principal, state, currentAuthorizedScopes, null);
        }

        OAuth2TokenContext tokenContext = createAuthorizationCodeTokenContext(
                authorizationCodeRequestAuthentication, registeredApp, null, authorizationRequest.getScopes());
        OAuth2AuthorizationCode authorizationCode = this.authorizationCodeGenerator.generate(tokenContext);
        if (authorizationCode == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the authorization code.", ERROR_URI);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated authorization code");
        }

        OAuth2Authorization authorization = authorizationBuilder(registeredApp, principal, authorizationRequest)
                .authorizedScopes(authorizationRequest.getScopes())
                .token(authorizationCode)
                .build();
        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        String redirectUri = authorizationRequest.getRedirectUri();
        if (!StringUtils.hasText(redirectUri)) {
            redirectUri = registeredApp.getRedirectUris().iterator().next();
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated authorization code request");
        }

        return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationRequest.getAuthorizationUri(),
                registeredApp.getAppId(), principal, authorizationCode, redirectUri,
                authorizationRequest.getState(), authorizationRequest.getScopes());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2AuthorizationCodeRequestAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public OAuth2AuthorizationCodeRequestAuthenticationProvider setRegisteredAppRepository(RegisteredAppRepository registeredAppRepository) {
        this.registeredAppRepository = registeredAppRepository;
        return this;
    }

    public OAuth2AuthorizationCodeRequestAuthenticationProvider setAuthorizationCodeGenerator(OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
        this.authorizationCodeGenerator = authorizationCodeGenerator;
        return this;
    }

    public OAuth2AuthorizationCodeRequestAuthenticationProvider setAuthorizationConsentService(OAuth2AuthorizationConsentService authorizationConsentService) {
        this.authorizationConsentService = authorizationConsentService;
        return this;
    }

    public OAuth2AuthorizationCodeRequestAuthenticationProvider setAuthorizationService(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
        return this;
    }

    private static OAuth2TokenContext createAuthorizationCodeTokenContext(
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            RegisteredApp registeredClient, OAuth2Authorization authorization, Set<String> authorizedScopes) {

        // @formatter:off
        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal((Authentication) authorizationCodeRequestAuthentication.getPrincipal())
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .tokenType(new OAuth2TokenType(OAuth2ParameterNames.CODE))
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrant(authorizationCodeRequestAuthentication);
        // @formatter:on

        if (authorization != null) {
            tokenContextBuilder.authorization(authorization);
        }

        return tokenContextBuilder.build();
    }

    private static OAuth2Authorization.Builder authorizationBuilder(RegisteredApp registeredApp, Authentication principal,
                                                                    OAuth2AuthorizationRequest authorizationRequest) {
        return OAuth2Authorization.withRegisteredApp(registeredApp)
                .principalName(principal.getName())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), principal)
                .attribute(OAuth2AuthorizationRequest.class.getName(), authorizationRequest);
    }

    private static boolean requireAuthorizationConsent(RegisteredApp registeredApp,
                                                       OAuth2AuthorizationRequest authorizationRequest, OAuth2AuthorizationConsent authorizationConsent) {
        if (!registeredApp.isRequireAuthorizationConsent()) {
            return false;
        }


        if (authorizationConsent != null &&
                authorizationConsent.getScopes().containsAll(authorizationRequest.getScopes())) {
            return false;
        }

        return true;
    }
    private static boolean isPrincipalAuthenticated(Authentication principal) {
        return principal != null &&
                !AnonymousAuthenticationToken.class.isAssignableFrom(principal.getClass()) &&
                principal.isAuthenticated();
    }

    private static void throwError(String errorCode, String parameterName,
                                   OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                   RegisteredApp registeredApp) {
        throwError(errorCode, parameterName, ERROR_URI, authorizationCodeRequestAuthentication, registeredApp, null);
    }

    private static void throwError(String errorCode, String parameterName, String errorUri,
                                   OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                   RegisteredApp registeredApp, OAuth2AuthorizationRequest authorizationRequest) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throwError(error, parameterName, authorizationCodeRequestAuthentication, registeredApp, authorizationRequest);
    }

    private static void throwError(OAuth2Error error, String parameterName,
                                   OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                   RegisteredApp registeredApp, OAuth2AuthorizationRequest authorizationRequest) {

        String redirectUri = resolveRedirectUri(authorizationCodeRequestAuthentication, authorizationRequest, registeredApp);
        if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST) &&
                (parameterName.equals(OAuth2ParameterNames.APP_ID) ||
                        parameterName.equals(OAuth2ParameterNames.STATE))) {
            redirectUri = null;		// Prevent redirects
        }

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult =
                new OAuth2AuthorizationCodeRequestAuthenticationToken(
                        authorizationCodeRequestAuthentication.getAuthorizationUri(), authorizationCodeRequestAuthentication.getAppId(),
                        (Authentication) authorizationCodeRequestAuthentication.getPrincipal(), redirectUri,
                        authorizationCodeRequestAuthentication.getState(), authorizationCodeRequestAuthentication.getScopes(),
                        authorizationCodeRequestAuthentication.getAdditionalParameters());

        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, authorizationCodeRequestAuthenticationResult);
    }

    private static String resolveRedirectUri(
            OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
            OAuth2AuthorizationRequest authorizationRequest, RegisteredApp registeredApp) {

        if (authorizationCodeRequestAuthentication != null && StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
            return authorizationCodeRequestAuthentication.getRedirectUri();
        }
        if (authorizationRequest != null && StringUtils.hasText(authorizationRequest.getRedirectUri())) {
            return authorizationRequest.getRedirectUri();
        }
        if (registeredApp != null) {
            return registeredApp.getRedirectUris().iterator().next();
        }
        return null;
    }
}
