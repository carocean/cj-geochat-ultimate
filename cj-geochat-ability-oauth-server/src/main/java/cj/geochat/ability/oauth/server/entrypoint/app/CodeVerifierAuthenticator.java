package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

final class CodeVerifierAuthenticator {
	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);
	private final Log logger = LogFactory.getLog(getClass());
	private final OAuth2AuthorizationService authorizationService;

	CodeVerifierAuthenticator(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	void authenticateRequired(AppAuthenticationToken clientAuthentication,
							  RegisteredApp registeredClient) {
		if (!authenticate(clientAuthentication, registeredClient)) {
			throwInvalidGrant(PkceParameterNames.CODE_VERIFIER);
		}
	}

	void authenticateIfAvailable(AppAuthenticationToken clientAuthentication,
								 RegisteredApp registeredClient) {
		authenticate(clientAuthentication, registeredClient);
	}

	private boolean authenticate(AppAuthenticationToken clientAuthentication,
								 RegisteredApp registeredApp) {

		Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
		if (!authorizationCodeGrant(parameters)) {
			return false;
		}

		OAuth2Authorization authorization = this.authorizationService.findByToken(
				(String) parameters.get(OAuth2ParameterNames.CODE),
				AUTHORIZATION_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throwInvalidGrant(OAuth2ParameterNames.CODE);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated code verifier");
		}

		return true;
	}

	private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
		return AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(
				parameters.get(OAuth2ParameterNames.GRANT_TYPE)) &&
				parameters.get(OAuth2ParameterNames.CODE) != null;
	}

	private static boolean codeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
		if (!StringUtils.hasText(codeVerifier)) {
			return false;
		} else if ("S256".equals(codeChallengeMethod)) {
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
				String encodedVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
				return encodedVerifier.equals(codeChallenge);
			} catch (NoSuchAlgorithmException ex) {
				// It is unlikely that SHA-256 is not available on the server. If it is not available,
				// there will likely be bigger issues as well. We default to SERVER_ERROR.
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
			}
		}
		return false;
	}

	private static void throwInvalidGrant(String parameterName) {
		OAuth2Error error = new OAuth2Error(
				OAuth2ErrorCodes.INVALID_GRANT,
				"Client authentication failed: " + parameterName,
				null
		);
		throw new OAuth2AuthenticationException(error);
	}

}