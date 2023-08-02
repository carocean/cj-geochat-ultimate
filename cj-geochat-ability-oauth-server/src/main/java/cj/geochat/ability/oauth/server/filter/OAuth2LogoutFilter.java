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
import org.springframework.core.log.LogMessage;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class OAuth2LogoutFilter extends OncePerRequestFilter {
    private AuthenticationSuccessHandler successHandler = this::successHandler;

    private AuthenticationFailureHandler failureHandler = this::failureHandler;
    private RequestMatcher requestMatcher;
    private OAuth2AuthorizationService authorizationService;

    public OAuth2LogoutFilter(RequestMatcher requestMatcher) {
        this.requestMatcher = requestMatcher;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            var params = OAuth2EndpointUtils.getParameters(request);
            String token = params.getFirst("token");
            if (!StringUtils.hasText(token)) {
                token = request.getHeader("token");
            }
            if (!StringUtils.hasText(token)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Missing parameter: token", null);
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            }
            var authToken = authorizationService.findByToken(token, OAuth2TokenType.ACCESS_TOKEN);
            if (authToken == null) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Token does not exist", null);
                throw new OAuth2AuthorizationCodeRequestAuthenticationException(error, null);
            }
            authorizationService.remove(authToken);

            if (successHandler != null) {
                successHandler(request, response, SecurityContextHolder.getContext().getAuthentication());
            }

            SecurityContextHolder.clearContext();

        } catch (OAuth2AuthenticationException ex) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Logout request failed: %s", ex.getError()), ex);
            }
            this.failureHandler.onAuthenticationFailure(request, response, ex);
        }
    }

    private void successHandler(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCode.IS_LOGOUT;
        Map<String, String> map = new HashMap<>();
        if (authentication == null) {
            map.put("description", "Logged out. ");
        } else {
            map.put("user", authentication.getName());
        }
        Object obj = R.of(rc, map);
        response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
    }

    private void failureHandler(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCode.IS_LOGOUT_FAILURE;
        Map<String, String> map = new HashMap<>();
        map.put("description", exception.getMessage());
        Object obj = R.of(rc, map);
        response.getWriter().write(new ObjectMapper().writeValueAsString(obj));
//
    }
    public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
        if (successHandler == null) {
            return;
        }
        this.successHandler = successHandler;
    }

    public void setAuthorizationService(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        if (failureHandler == null) {
            return;
        }
        this.failureHandler = failureHandler;
    }

}
