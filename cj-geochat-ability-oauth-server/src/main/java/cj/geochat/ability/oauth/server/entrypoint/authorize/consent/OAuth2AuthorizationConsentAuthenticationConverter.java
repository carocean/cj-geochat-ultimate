package cj.geochat.ability.oauth.server.entrypoint.authorize.consent;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

@CjAuthConverter("consent")
public class OAuth2AuthorizationConsentAuthenticationConverter implements IAuthenticationConverter {
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final Authentication ANONYMOUS_AUTHENTICATION = new AnonymousAuthenticationToken(
            "anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {
        if (!"POST".equals(request.getMethod())) {
            return null;
        }

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        String authorizationUri = request.getRequestURL().toString();

        // client_id (REQUIRED)
        String appId = parameters.getFirst(OAuth2ParameterNames.APP_ID);
        if (!StringUtils.hasText(appId) ||
                parameters.get(OAuth2ParameterNames.APP_ID).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.APP_ID);
        }

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            principal = ANONYMOUS_AUTHENTICATION;
        }

        // state (REQUIRED)
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        if (!StringUtils.hasText(state) ||
                parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        // scope (OPTIONAL)
        Set<String> scopes = null;
        if (parameters.containsKey(OAuth2ParameterNames.SCOPE)) {
            scopes = new HashSet<>(parameters.get(OAuth2ParameterNames.SCOPE));
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.APP_ID) &&
                    !key.equals(OAuth2ParameterNames.STATE) &&
                    !key.equals(OAuth2ParameterNames.SCOPE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        return new OAuth2AuthorizationConsentAuthenticationToken(authorizationUri, appId, principal,
                state, scopes, additionalParameters);
    }

    private static void throwError(String errorCode, String parameterName) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, DEFAULT_ERROR_URI);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }
}
