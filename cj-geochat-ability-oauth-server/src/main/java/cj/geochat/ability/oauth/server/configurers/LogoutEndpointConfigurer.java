package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.OAuth2ConfigurerUtils;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.filter.OAuth2LogoutFilter;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import cj.geochat.ability.oauth.server.util.SecurityBeanUtil;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class LogoutEndpointConfigurer extends AbstractHttpConfigurer<LogoutEndpointConfigurer, HttpSecurity> {

    private AuthenticationSuccessHandler successHandler;

    private AuthenticationFailureHandler failureHandler;
    private RequestMatcher requestMatcher;
    private OAuth2AuthorizationService authorizationService;
    private IAuthenticationConverter converter;

    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(
                        authorizationServerSettings.getLogoutEndpoint(),
                        HttpMethod.POST.name()
                ), new AntPathRequestMatcher(
                authorizationServerSettings.getLogoutEndpoint(),
                HttpMethod.GET.name()));
        if (authorizationService == null) {
            authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);
        }
        if (successHandler == null) {
            successHandler = (AuthenticationSuccessHandler) SecurityBeanUtil.getBean(httpSecurity, "logoutSuccessHandler", null);
        }
        if (failureHandler == null) {
            failureHandler = (AuthenticationFailureHandler) SecurityBeanUtil.getBean(httpSecurity, "logoutFailureHandler", null);
        }
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        OAuth2LogoutFilter logoutFilter = new OAuth2LogoutFilter(this.requestMatcher);
        logoutFilter.setAuthorizationService(authorizationService);
        logoutFilter.setFailureHandler(failureHandler);
        logoutFilter.setSuccessHandler(successHandler);
        http.addFilterAfter(this.postProcess(logoutFilter), AuthorizationFilter.class);
    }

    public LogoutEndpointConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    public LogoutEndpointConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }
}
