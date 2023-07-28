package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.repository.RegisteredAppRepository;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.Assert;

public final class PublicAppAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";
	private final Log logger = LogFactory.getLog(getClass());
	private final RegisteredAppRepository registeredAppRepository;
	private final CodeVerifierAuthenticator codeVerifierAuthenticator;

	/**
	 * Constructs a {@code PublicClientAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredAppRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public PublicAppAuthenticationProvider(RegisteredAppRepository registeredAppRepository,
										   OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredAppRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredAppRepository = registeredAppRepository;
		this.codeVerifierAuthenticator = new CodeVerifierAuthenticator(authorizationService);
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AppAuthenticationToken clientAuthentication =
				(AppAuthenticationToken) authentication;

		if (!AppAuthenticationMethod.NONE.equals(clientAuthentication.getAppAuthenticationMethod())) {
			return null;
		}

		String appId = clientAuthentication.getPrincipal().toString();
		RegisteredApp registeredClient = this.registeredAppRepository.findByAppId(appId);
		if (registeredClient == null) {
			throwInvalidClient(OAuth2ParameterNames.APP_ID);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

//		if (!registeredClient.getAppAuthenticationMethod().contains(
//				clientAuthentication.getAppAuthenticationMethod())) {
//			throwInvalidClient("authentication_method");
//		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client authentication parameters");
		}

		// Validate the "code_verifier" parameter for the public client
		this.codeVerifierAuthenticator.authenticateRequired(clientAuthentication, registeredClient);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated public client");
		}

		return new AppAuthenticationToken(registeredClient,
				clientAuthentication.getAppAuthenticationMethod(), null);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return AppAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static void throwInvalidClient(String parameterName) {
		OAuth2Error error = new OAuth2Error(
				OAuth2ErrorCodes.INVALID_CLIENT,
				"Client authentication failed: " + parameterName,
				ERROR_URI
		);
		throw new OAuth2AuthenticationException(error);
	}

}