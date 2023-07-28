package cj.geochat.ability.oauth.server.entrypoint.app;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
@CjAuthConverter("none")
public final class PublicAppAuthenticationConverter implements IAuthenticationConverter {

	@Nullable
	@Override
	public AbstractAuthenticationToken convert(HttpServletRequest request) {
		if (!OAuth2EndpointUtils.matchesPkceTokenRequest(request)) {
			return null;
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// client_id (REQUIRED for public clients)
		String clientId = parameters.getFirst(OAuth2ParameterNames.APP_ID);
		if (!StringUtils.hasText(clientId) ||
				parameters.get(OAuth2ParameterNames.APP_ID).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		// code_verifier (REQUIRED)
		if (parameters.get(PkceParameterNames.CODE_VERIFIER).size() != 1) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
		}

		parameters.remove(OAuth2ParameterNames.APP_ID);

		return new AppAuthenticationToken(clientId, AppAuthenticationMethod.NONE, null,
				new HashMap<>(parameters.toSingleValueMap()));
	}
}