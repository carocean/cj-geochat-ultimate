package cj.geochat.ability.oauth.server.entrypoint.authorize.request;

import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

@CjAuthConverter("code")
public class OAuth2AuthorizationCodeRequestAuthenticationConverter implements IAuthenticationConverter {
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";
    private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";

    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        // response_type (REQUIRED)
        String responseType = request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE);
        if (!StringUtils.hasText(responseType) ||
                parameters.get(OAuth2ParameterNames.RESPONSE_TYPE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.RESPONSE_TYPE);
        } else if (!responseType.equals(OAuth2AuthorizationResponseType.CODE.getValue())) {
            throwError(OAuth2ErrorCodes.UNSUPPORTED_RESPONSE_TYPE, OAuth2ParameterNames.RESPONSE_TYPE);
        }

        String authorizationUri = request.getRequestURL().toString();

        // client_id (REQUIRED)
        String clientId = parameters.getFirst(OAuth2ParameterNames.APP_ID);
        if (!StringUtils.hasText(clientId) ||
                parameters.get(OAuth2ParameterNames.APP_ID).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.APP_ID);
        }

        Authentication principal = SecurityContextHolder.getContext().getAuthentication();
        if (principal == null) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.UNAUTHENTICATED);
        }

        // redirect_uri (OPTIONAL)
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri) &&
                parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI);
        }

        // scope (OPTIONAL)
        Set<String> scopes = null;
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
                parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE);
        }
        if (StringUtils.hasText(scope)) {
            scopes = new HashSet<>(
                    Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // state (RECOMMENDED)
        String state = parameters.getFirst(OAuth2ParameterNames.STATE);
        if (StringUtils.hasText(state) &&
                parameters.get(OAuth2ParameterNames.STATE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.STATE);
        }

        // code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
        String codeChallenge = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE);
        if (StringUtils.hasText(codeChallenge) &&
                parameters.get(PkceParameterNames.CODE_CHALLENGE).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI);
        }

        // code_challenge_method (OPTIONAL for public clients) - RFC 7636 (PKCE)
        String codeChallengeMethod = parameters.getFirst(PkceParameterNames.CODE_CHALLENGE_METHOD);
        if (StringUtils.hasText(codeChallengeMethod) &&
                parameters.get(PkceParameterNames.CODE_CHALLENGE_METHOD).size() != 1) {
            throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.RESPONSE_TYPE) &&
                    !key.equals(OAuth2ParameterNames.APP_ID) &&
                    !key.equals(OAuth2ParameterNames.REDIRECT_URI) &&
                    !key.equals(OAuth2ParameterNames.SCOPE) &&
                    !key.equals(OAuth2ParameterNames.STATE)) {
                additionalParameters.put(key, value.get(0));
            }
        });
        return new OAuth2AuthorizationCodeRequestAuthenticationToken(authorizationUri, clientId, principal,
                redirectUri, state, scopes, additionalParameters);
    }

    private static void throwError(String errorCode, String parameterName) {
        throwError(errorCode, parameterName, DEFAULT_ERROR_URI);
    }

    private static void throwError(String errorCode, String parameterName, String errorUri) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
        throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
    }
}
