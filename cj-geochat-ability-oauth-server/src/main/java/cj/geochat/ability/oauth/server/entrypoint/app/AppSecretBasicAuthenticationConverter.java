package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.StringUtils;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@CjAuthConverter("app_secret_basic")
public final class AppSecretBasicAuthenticationConverter implements IAuthenticationConverter {

	@Nullable
	@Override
	public AbstractAuthenticationToken convert(HttpServletRequest request) {
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null) {
			return null;
		}

		String[] parts = header.split("\\s");
		if (!parts[0].equalsIgnoreCase("Basic")) {
			return null;
		}

		if (parts.length != 2) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		byte[] decodedCredentials;
		try {
			decodedCredentials = Base64.getDecoder().decode(
					parts[1].getBytes(StandardCharsets.UTF_8));
		} catch (IllegalArgumentException ex) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex);
		}

		String credentialsString = new String(decodedCredentials, StandardCharsets.UTF_8);
		String[] credentials = credentialsString.split(":", 2);
		if (credentials.length != 2 ||
				!StringUtils.hasText(credentials[0]) ||
				!StringUtils.hasText(credentials[1])) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		String clientID;
		String clientSecret;
		try {
			clientID = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8.name());
			clientSecret = URLDecoder.decode(credentials[1], StandardCharsets.UTF_8.name());
		} catch (Exception ex) {
			throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex);
		}

		return new AppAuthenticationToken(clientID, AppAuthenticationMethod.APP_SECRET_BASIC, clientSecret,
				OAuth2EndpointUtils.getParametersIfMatchesAuthorizationCodeGrantRequest(request));
	}

}