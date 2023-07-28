package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.repository.RegisteredAppRepository;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.Assert;

import java.time.Instant;

public final class AppSecretAuthenticationProvider implements AuthenticationProvider {
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";
	private final Log logger = LogFactory.getLog(getClass());
	private final RegisteredAppRepository registeredAppRepository;
	private final CodeVerifierAuthenticator codeVerifierAuthenticator;
	private PasswordEncoder passwordEncoder;

	/**
	 * Constructs a {@code ClientSecretAuthenticationProvider} using the provided parameters.
	 *
	 * @param registeredAppRepository the repository of registered clients
	 * @param authorizationService the authorization service
	 */
	public AppSecretAuthenticationProvider(RegisteredAppRepository registeredAppRepository,
										   OAuth2AuthorizationService authorizationService) {
		Assert.notNull(registeredAppRepository, "registeredClientRepository cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.registeredAppRepository = registeredAppRepository;
		this.codeVerifierAuthenticator = new CodeVerifierAuthenticator(authorizationService);
		this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}


	public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
		Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AppAuthenticationToken appAuthentication =
				(AppAuthenticationToken) authentication;

		if (!AppAuthenticationMethod.APP_SECRET_BASIC.equals(appAuthentication.getAppAuthenticationMethod()) &&
				!AppAuthenticationMethod.APP_SECRET_POST.equals(appAuthentication.getAppAuthenticationMethod())) {
			return null;
		}

		String appId = appAuthentication.getPrincipal().toString();
		RegisteredApp registeredApp = this.registeredAppRepository.findByAppId(appId);
		if (registeredApp == null) {
			throwInvalidClient(OAuth2ParameterNames.APP_ID);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

//		if (!registeredApp.getAppAuthenticationMethod().contains(
//				appAuthentication.getAppAuthenticationMethod())) {
//			throwInvalidClient("authentication_method");
//		}

		if (appAuthentication.getCredentials() == null) {
			throwInvalidClient("credentials");
		}

		String clientSecret = appAuthentication.getCredentials().toString();
		if (!this.passwordEncoder.matches(clientSecret, registeredApp.getAppSecret())) {
			throwInvalidClient(OAuth2ParameterNames.APP_SECRET);
		}

		if (registeredApp.getAppSecretExpiresAt() != null &&
				Instant.now().isAfter(registeredApp.getAppSecretExpiresAt())) {
			throwInvalidClient("client_secret_expires_at");
		}

		if (this.passwordEncoder.upgradeEncoding(registeredApp.getAppSecret())) {
			registeredApp = RegisteredApp.from(registeredApp)
					.appSecret(this.passwordEncoder.encode(clientSecret))
					.build();
			this.registeredAppRepository.save(registeredApp);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated client authentication parameters");
		}

		// Validate the "code_verifier" parameter for the confidential client, if available
		this.codeVerifierAuthenticator.authenticateIfAvailable(appAuthentication, registeredApp);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated client secret");
		}

		return new AppAuthenticationToken(registeredApp,
				appAuthentication.getAppAuthenticationMethod(), appAuthentication.getCredentials());
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