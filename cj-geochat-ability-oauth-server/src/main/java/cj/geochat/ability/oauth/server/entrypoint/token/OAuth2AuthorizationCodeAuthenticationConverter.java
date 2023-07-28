package cj.geochat.ability.oauth.server.entrypoint.token;

import cj.geochat.ability.oauth.server.AuthorizationGrantType;
import cj.geochat.ability.oauth.server.OAuth2EndpointUtils;
import cj.geochat.ability.oauth.server.OAuth2ErrorCodes;
import cj.geochat.ability.oauth.server.OAuth2ParameterNames;
import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;
@CjAuthConverter("authorization_code")
public class OAuth2AuthorizationCodeAuthenticationConverter implements IAuthenticationConverter {
    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
            return null;
        }

        Authentication appPrincipal = SecurityContextHolder.getContext().getAuthentication();

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        // code (REQUIRED)
        String code = parameters.getFirst(OAuth2ParameterNames.CODE);
        if (!StringUtils.hasText(code) ||
                parameters.get(OAuth2ParameterNames.CODE).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.CODE,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // redirect_uri (REQUIRED)
        // Required only if the "redirect_uri" parameter was included in the authorization request
        String redirectUri = parameters.getFirst(OAuth2ParameterNames.REDIRECT_URI);
        if (StringUtils.hasText(redirectUri) &&
                parameters.get(OAuth2ParameterNames.REDIRECT_URI).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.REDIRECT_URI,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.APP_ID) &&
                    !key.equals(OAuth2ParameterNames.CODE) &&
                    !key.equals(OAuth2ParameterNames.REDIRECT_URI)) {
                additionalParameters.put(key, value.get(0));
            }
        });
        return new OAuth2AuthorizationCodeAuthenticationToken(
                code, appPrincipal, redirectUri, additionalParameters);
    }
}
