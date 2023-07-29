package cj.geochat.ability.oauth.gateway;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ServerBearerTokenAuthenticationConverter implements ServerAuthenticationConverter {
    private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$", 2);
    private boolean allowUriQueryParameter = false;
    private String bearerTokenHeaderName = "Authorization";

    public ServerBearerTokenAuthenticationConverter(boolean allowUriQueryParameter) {
        this.allowUriQueryParameter=allowUriQueryParameter;
    }

    public Mono<Authentication> convert(ServerWebExchange exchange) {
        return Mono.fromCallable(() -> {
            return this.token(exchange.getRequest());
        }).map((token) -> {
            if (token.isEmpty()) {
                BearerTokenError error = invalidTokenError();
                throw new OAuth2AuthenticationException(error);
            } else {
                return new BearerTokenAuthenticationToken(token);
            }
        });
    }

    private String token(ServerHttpRequest request) {
        String authorizationHeaderToken = this.resolveFromAuthorizationHeader(request.getHeaders());
        String parameterToken = resolveAccessTokenFromRequest(request);
        if (authorizationHeaderToken != null) {
            if (parameterToken != null) {
                BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
                throw new OAuth2AuthenticationException(error);
            } else {
                return authorizationHeaderToken;
            }
        } else {
            return parameterToken != null && this.isParameterTokenSupportedForRequest(request) ? parameterToken : null;
        }
    }

    private static String resolveAccessTokenFromRequest(ServerHttpRequest request) {
        List<String> parameterTokens = (List)request.getQueryParams().get("access_token");
        if (CollectionUtils.isEmpty(parameterTokens)) {
            return null;
        } else if (parameterTokens.size() == 1) {
            return (String)parameterTokens.get(0);
        } else {
            BearerTokenError error = BearerTokenErrors.invalidRequest("Found multiple bearer tokens in the request");
            throw new OAuth2AuthenticationException(error);
        }
    }

    public void setAllowUriQueryParameter(boolean allowUriQueryParameter) {
        this.allowUriQueryParameter = allowUriQueryParameter;
    }

    public void setBearerTokenHeaderName(String bearerTokenHeaderName) {
        this.bearerTokenHeaderName = bearerTokenHeaderName;
    }

    private String resolveFromAuthorizationHeader(HttpHeaders headers) {
        String authorization = headers.getFirst(this.bearerTokenHeaderName);
        if (!StringUtils.startsWithIgnoreCase(authorization, "bearer")) {
            return null;
        } else {
            Matcher matcher = authorizationPattern.matcher(authorization);
            if (!matcher.matches()) {
                BearerTokenError error = invalidTokenError();
                throw new OAuth2AuthenticationException(error);
            } else {
                return matcher.group("token");
            }
        }
    }

    private static BearerTokenError invalidTokenError() {
        return BearerTokenErrors.invalidToken("Bearer token is malformed");
    }

    private boolean isParameterTokenSupportedForRequest(ServerHttpRequest request) {
        return this.allowUriQueryParameter && HttpMethod.GET.equals(request.getMethod());
    }
}
