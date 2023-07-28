package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Map;
@CjAuthConverter("app_secret_post")
public final class AppSecretPostAuthenticationConverter implements IAuthenticationConverter {

	@Nullable
	@Override
	public AbstractAuthenticationToken convert(HttpServletRequest request) {
		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// client_id (REQUIRED)
		String appId = parameters.getFirst(OAuth2ParameterNames.APP_ID);
		if (!StringUtils.hasText(appId)) {
			return null;
		}

		if (parameters.get(OAuth2ParameterNames.APP_ID).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		// client_secret (REQUIRED)
		String clientSecret = parameters.getFirst(OAuth2ParameterNames.APP_SECRET);
		if (!StringUtils.hasText(clientSecret)) {
			return null;
		}

		if (parameters.get(OAuth2ParameterNames.APP_SECRET).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		Map<String, Object> additionalParameters = OAuth2EndpointUtils.getParametersIfMatchesAuthorizationCodeGrantRequest(request,
				OAuth2ParameterNames.APP_ID,
				OAuth2ParameterNames.APP_SECRET);

		return new AppAuthenticationToken(appId, AppAuthenticationMethod.APP_SECRET_POST, clientSecret,
				additionalParameters);
	}

}
