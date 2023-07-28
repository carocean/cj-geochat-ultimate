package cj.geochat.ability.oauth.app.resolver;

import cj.geochat.ability.oauth.app.BearerTokenError;
import cj.geochat.ability.oauth.app.BearerTokenErrors;
import cj.geochat.ability.oauth.app.BearerTokenResolver;
import cj.geochat.ability.oauth.app.OAuth2AuthenticationException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class DefaultBearerTokenResolver implements BearerTokenResolver {
    private static final String ACCESS_TOKEN_PARAMETER_NAME = "access_token";
    private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$", 2);
    private boolean allowFormEncodedBodyParameter = true;
    private boolean allowUriQueryParameter = true;
    private String bearerTokenHeaderName = "Authorization";

    public DefaultBearerTokenResolver() {
    }

    public String resolve(final HttpServletRequest request) {
        String authorizationHeaderToken = this.resolveFromAuthorizationHeader(request);
        String parameterToken = this.isParameterTokenSupportedForRequest(request) ? resolveFromRequestParameters(request) : null;
        if (authorizationHeaderToken != null) {
            if (parameterToken != null) {
                BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            } else {
                return authorizationHeaderToken;
            }
        } else {
            return parameterToken != null && this.isParameterTokenEnabledForRequest(request) ? parameterToken : null;
        }
    }

    public void setAllowFormEncodedBodyParameter(boolean allowFormEncodedBodyParameter) {
        this.allowFormEncodedBodyParameter = allowFormEncodedBodyParameter;
    }

    public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
        this.allowUriQueryParameter = allowUriQueryParameter;
    }

    public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
        this.bearerTokenHeaderName = bearerTokenHeaderName;
    }

    private String resolveFromAuthorizationHeader(HttpServletRequest request) {
        String authorization = request.getHeader(this.bearerTokenHeaderName);
        if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
            return null;
        } else {
            Matcher matcher = authorizationPattern.matcher(authorization);
            if (!matcher.matches()) {
                BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
                throw new OAuth2AuthenticationException(error);
            } else {
                return matcher.group("token");
            }
        }
    }

    private static String resolveFromRequestParameters(HttpServletRequest request) {
        String[] values = request.getParameterValues("access_token");
        if (values != null && values.length != 0) {
            if (values.length == 1) {
                return values[0];
            } else {
                BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            }
        } else {
            return null;
        }
    }

    private boolean isParameterTokenSupportedForRequest(final HttpServletRequest request) {
        return isFormEncodedRequest(request) || isGetRequest(request);
    }

    private static boolean isGetRequest(HttpServletRequest request) {
        return HttpMethod.GET.name().equals(request.getMethod());
    }

    private static boolean isFormEncodedRequest(HttpServletRequest request) {
        return "application/x-www-form-urlencoded".equals(request.getContentType());
    }

    private static boolean hasAccessTokenInQueryString(HttpServletRequest request) {
        return request.getQueryString() != null && request.getQueryString().contains("access_token");
    }

    private boolean isParameterTokenEnabledForRequest(HttpServletRequest request) {
        return this.allowFormEncodedBodyParameter && isFormEncodedRequest(request) && !isGetRequest(request) && !hasAccessTokenInQueryString(request) || this.allowUriQueryParameter && isGetRequest(request);
    }
}
