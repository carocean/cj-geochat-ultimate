package cj.geochat.ability.oauth.server.filter;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.stream.Collectors;

public class OAuth2CheckTokenEndpointFilter extends OncePerRequestFilter {
    private final RequestMatcher checkTokenEndpointMatcher;
    private OAuth2AuthorizationService authorizationService;

    public OAuth2CheckTokenEndpointFilter(OAuth2AuthorizationService authorizationService, String tokenEndpointUri) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.hasText(tokenEndpointUri, "tokenEndpointUri cannot be empty");
        this.authorizationService = authorizationService;
        this.checkTokenEndpointMatcher = new AntPathRequestMatcher(tokenEndpointUri, HttpMethod.POST.name());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!this.checkTokenEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        var params = OAuth2EndpointUtils.getParameters(request);
        String token = params.getFirst("token");
        if (!StringUtils.hasText(token)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter: token", null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,null);
        }
        var authToken = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
        if (authToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Token does not exist", null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,null);
        }

        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCode.SUCCESS_CHECK;

        var map = new LinkedHashMap<>();
        AbstractAuthenticationToken principal = authToken.getAttribute(Principal.class.getName());
        var authorities = principal.getAuthorities();
        var scopes = authToken.getAuthorizedScopes();
        var newAuthorities = scopes.stream().map(e -> String.format("SCOPE_%s", e))
                .collect(Collectors.toList());
        newAuthorities.addAll(0, authorities.stream().map(e -> e.getAuthority()).collect(Collectors.toList()));
        var accessToken = authToken.getAccessToken();
        var oauth2Request = (OAuth2AuthorizationRequest) authToken.getAttribute(OAuth2AuthorizationRequest.class.getName());
        map.put("principal_name", authToken.getPrincipalName());
        if (principal.getPrincipal() instanceof User user) {
            map.put("principal_is_enabled", user.isEnabled());
            map.put("principal_is_account_non_expired", user.isAccountNonExpired());
            map.put("principal_is_account_non_locked", user.isAccountNonLocked());
            map.put("principal_is_credentials_non_expired", user.isCredentialsNonExpired());
        }
        map.put("app_id", oauth2Request.getAppId());
        map.put("state", oauth2Request.getState());
        map.put("redirect_uri", oauth2Request.getRedirectUri());
        map.put("authorities", newAuthorities.stream().collect(Collectors.joining(",")));
        map.put("token_is_expired", accessToken.isExpired());
        map.put("token_is_active", accessToken.isActive());
        map.put("token_is_invalidated", accessToken.isInvalidated());
        Object obj = R.of(rc, map);
        response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));
    }
}
