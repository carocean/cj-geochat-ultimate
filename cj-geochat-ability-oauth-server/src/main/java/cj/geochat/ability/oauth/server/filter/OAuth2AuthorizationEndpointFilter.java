package cj.geochat.ability.oauth.server.filter;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.convert.DelegatingResponseTypeConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.authorize.consent.OAuth2AuthorizationConsentAuthenticationToken;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.RedirectUrlBuilder;
import org.springframework.security.web.util.matcher.*;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

///参考spring oauth2的对应类：OAuth2AuthorizationEndpointFilter
public class OAuth2AuthorizationEndpointFilter extends OncePerRequestFilter {
    private final RequestMatcher authorizationEndpointMatcher;
    private IAuthenticationConverter authenticationConverter;
    private AuthenticationManager authenticationManager;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAuthorizationResponse;
    private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;
    private SessionAuthenticationStrategy sessionAuthenticationStrategy = (authentication, request, response) -> {
    };

    public OAuth2AuthorizationEndpointFilter(AuthenticationManager authenticationManager, String endpointPage) {
        this.authenticationManager = authenticationManager;
        this.authorizationEndpointMatcher = createDefaultRequestMatcher(endpointPage);
    }

    private static RequestMatcher createDefaultRequestMatcher(String authorizationEndpointUri) {
        RequestMatcher authorizationRequestGetMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.GET.name());
        RequestMatcher authorizationRequestPostMatcher = new AntPathRequestMatcher(
                authorizationEndpointUri, HttpMethod.POST.name());

        RequestMatcher responseTypeParameterMatcher = request ->
                request.getParameter(OAuth2ParameterNames.RESPONSE_TYPE) != null;

        RequestMatcher authorizationRequestMatcher = new OrRequestMatcher(
                authorizationRequestGetMatcher,
                new AndRequestMatcher(
                        authorizationRequestPostMatcher, responseTypeParameterMatcher));
        RequestMatcher authorizationConsentMatcher = new AndRequestMatcher(
                authorizationRequestPostMatcher, new NegatedRequestMatcher(responseTypeParameterMatcher));

        return new OrRequestMatcher(authorizationRequestMatcher, authorizationConsentMatcher);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!this.authorizationEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            Authentication authentication = this.authenticationConverter.convert(request);
            if (authentication instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authentication)
                        .setDetails(this.authenticationDetailsSource.buildDetails(request));
            }
            Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

            if (!authenticationResult.isAuthenticated()) {
                // If the Principal (Resource Owner) is not authenticated then
                // pass through the chain with the expectation that the authentication process
                // will commence via AuthenticationEntryPoint
                filterChain.doFilter(request, response);
                return;
            }

            if (authenticationResult instanceof OAuth2AuthorizationConsentAuthenticationToken) {
                if (this.logger.isTraceEnabled()) {
                    this.logger.trace("Authorization consent is required");
                }
                sendAuthorizationConsent(request, response,
                        (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication,
                        (OAuth2AuthorizationConsentAuthenticationToken) authenticationResult);
                return;
            }

            this.sessionAuthenticationStrategy.onAuthentication(
                    authenticationResult, request, response);

            this.authenticationSuccessHandler.onAuthenticationSuccess(
                    request, response, authenticationResult);

        } catch (OAuth2AuthenticationException ex) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Authorization request failed: %s", ex.getError()), ex);
            }
            this.authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
        }
    }

    private void sendAuthorizationConsent(HttpServletRequest request, HttpServletResponse response,
                                          OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
                                          OAuth2AuthorizationConsentAuthenticationToken authorizationConsentAuthentication) throws IOException {

        String appId = authorizationConsentAuthentication.getAppId();
        Authentication principal = (Authentication) authorizationConsentAuthentication.getPrincipal();
        Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
//        Set<String> authorizedScopes = authorizationConsentAuthentication.getScopes();
        String state = authorizationConsentAuthentication.getState();

        String redirectUri = UriComponentsBuilder.fromUriString(resolveConsentUri(request))
                .queryParam(OAuth2ParameterNames.SCOPE, String.join(" ", requestedScopes))
                .queryParam(OAuth2ParameterNames.APP_ID, appId)
                .queryParam(OAuth2ParameterNames.STATE, state)
                .toUriString();

        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCode.REQUIRE_CONSENT;

        Map<String, Object> body = new HashMap<>();
        body.put("user", principal.getName());
        body.put("app_id", appId);
        body.put("redirect_uri", redirectUri);
        body.put("scope", requestedScopes.stream().collect(Collectors.joining(" ")));
        body.put("state", UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        Object obj = R.of(rc, body);
        response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));
    }

    private String resolveConsentUri(HttpServletRequest request) {
        RedirectUrlBuilder urlBuilder = new RedirectUrlBuilder();
        urlBuilder.setScheme(request.getScheme());
        urlBuilder.setServerName(request.getServerName());
        urlBuilder.setPort(request.getServerPort());
        urlBuilder.setContextPath(request.getContextPath());
        return urlBuilder.getUrl();
    }

    private void sendAuthorizationResponse(HttpServletRequest request, HttpServletResponse response,
                                           Authentication authentication) throws IOException {

        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
                .queryParam(OAuth2ParameterNames.CODE, authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
            uriBuilder.queryParam(
                    OAuth2ParameterNames.STATE,
                    UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        }

        String redirectUri = uriBuilder.build(true).toUriString();        // build(true) -> Components are explicitly encoded

        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCode.SUCCESS_CODE;

        Map<String, Object> body = new HashMap<>();
        body.put("user", authentication.getName());
        body.put("app_id", authorizationCodeRequestAuthentication.getAppId());
        body.put("redirect_uri", redirectUri);
        body.put("scope", authorizationCodeRequestAuthentication.getScopes().stream().collect(Collectors.joining(" ")));
        body.put("code", authorizationCodeRequestAuthentication.getAuthorizationCode().getTokenValue());
        body.put("state", UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        Object obj = R.of(rc, body);
        response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));
    }

    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationException exception) throws IOException {

        OAuth2AuthorizationCodeRequestAuthenticationException authorizationCodeRequestAuthenticationException =
                (OAuth2AuthorizationCodeRequestAuthenticationException) exception;
        OAuth2Error error = authorizationCodeRequestAuthenticationException.getError();
        OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication =
                authorizationCodeRequestAuthenticationException.getAuthorizationCodeRequestAuthentication();

        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCodeTranslator.translateException(exception);

        if (authorizationCodeRequestAuthentication == null ||
                !StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())) {
            Map<String, Object> body = new HashMap<>();
            body.put("errorCode", error.getErrorCode());
            body.put("description", error.getDescription());

            Object obj = R.of(rc, body);
            response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));
            return;
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Redirecting to client with error");
        }

        UriComponentsBuilder uriBuilder = UriComponentsBuilder
                .fromUriString(authorizationCodeRequestAuthentication.getRedirectUri())
                .queryParam(OAuth2ParameterNames.ERROR, error.getErrorCode());
        if (StringUtils.hasText(error.getDescription())) {
            uriBuilder.queryParam(
                    OAuth2ParameterNames.ERROR_DESCRIPTION,
                    UriUtils.encode(error.getDescription(), StandardCharsets.UTF_8));
        }
        if (StringUtils.hasText(error.getUri())) {
            uriBuilder.queryParam(
                    OAuth2ParameterNames.ERROR_URI,
                    UriUtils.encode(error.getUri(), StandardCharsets.UTF_8));
        }
        if (StringUtils.hasText(authorizationCodeRequestAuthentication.getState())) {
            uriBuilder.queryParam(
                    OAuth2ParameterNames.STATE,
                    UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        }
        String redirectUri = uriBuilder.build(true).toUriString();        // build(true) -> Components are explicitly encoded


        Map<String, Object> body = new HashMap<>();
        body.put("redirect_uri", redirectUri);
        body.put("state", UriUtils.encode(authorizationCodeRequestAuthentication.getState(), StandardCharsets.UTF_8));
        body.put("code", authorizationCodeRequestAuthentication.getAuthorizationCode());
        body.put("errorCode", error.getErrorCode());
        body.put("description", error.getDescription());
        Object obj = R.of(rc, body);
        response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));
    }

    public void setAuthenticationConverter(DelegatingResponseTypeConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
    }
}
