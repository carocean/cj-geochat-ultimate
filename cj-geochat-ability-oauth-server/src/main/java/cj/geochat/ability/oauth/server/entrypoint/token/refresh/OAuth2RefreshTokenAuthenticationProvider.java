package cj.geochat.ability.oauth.server.entrypoint.token.refresh;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.entrypoint.app.AppAuthenticationToken;
import cj.geochat.ability.oauth.server.entrypoint.token.OAuth2AccessTokenAuthenticationToken;
import cj.geochat.ability.oauth.server.generator.OAuth2TokenGenerator;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

public final class OAuth2RefreshTokenAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private final Log logger = LogFactory.getLog(getClass());
	private OAuth2AuthorizationService authorizationService;
	private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	public void setAuthorizationService(OAuth2AuthorizationService authorizationService) {
		this.authorizationService = authorizationService;
	}

	public void setTokenGenerator(OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		this.tokenGenerator = tokenGenerator;
	}

	static AppAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
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
		OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication =
				(OAuth2RefreshTokenAuthenticationToken) authentication;

		AppAuthenticationToken clientPrincipal =
				getAuthenticatedClientElseThrowInvalidClient(refreshTokenAuthentication);
		RegisteredApp registeredClient = clientPrincipal.getRegisteredApp();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with refresh token");
		}

		if (!registeredClient.getId().equals(authorization.getRegisteredAppId())) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
		}

		OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
		if (!refreshToken.isActive()) {
			// As per https://tools.ietf.org/html/rfc6749#section-5.2
			// invalid_grant: The provided authorization grant (e.g., authorization code,
			// resource owner credentials) or refresh token is invalid, expired, revoked [...].
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		// As per https://tools.ietf.org/html/rfc6749#section-6
		// The requested scope MUST NOT include any scope not originally granted by the resource owner,
		// and if omitted is treated as equal to the scope originally granted by the resource owner.
		Set<String> scopes = refreshTokenAuthentication.getScopes();
		Set<String> authorizedScopes = authorization.getAuthorizedScopes();
		if (!authorizedScopes.containsAll(scopes)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated token request parameters");
		}

		if (scopes.isEmpty()) {
			scopes = authorizedScopes;
		}

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(scopes)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrant(refreshTokenAuthentication);
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
		OAuth2RefreshToken currentRefreshToken = refreshToken.getToken();
		if (!registeredClient.isReuseRefreshTokens()) {
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

			currentRefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(currentRefreshToken);
		}



		authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		Map<String, Object> additionalParameters = Collections.emptyMap();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated token request");
		}

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, currentRefreshToken, additionalParameters);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

}