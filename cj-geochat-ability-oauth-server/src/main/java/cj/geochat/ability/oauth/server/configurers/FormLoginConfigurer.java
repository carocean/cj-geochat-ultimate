package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.DelegatingAuthTypeConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.filter.FormLoginFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

public class FormLoginConfigurer extends AbstractHttpConfigurer<FormLoginConfigurer, HttpSecurity> {
    private final List<IAuthenticationConverter> authenticationConverters = new ArrayList<>();
    private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

    private AuthenticationSuccessHandler successHandler;

    private AuthenticationFailureHandler failureHandler;
    private String defaultConverter;
    private String loginPage="/login";

    @Override
    public void init(HttpSecurity builder) throws Exception {
        super.init(builder);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher(loginPage, "POST");
        FormLoginFilter formLoginFilter = new FormLoginFilter(antPathRequestMatcher,
                authenticationManager);
        formLoginFilter.setSecurityContextRepository(getSecurityContextRepository());
        formLoginFilter.setAuthenticationSuccessHandler(successHandler);
        formLoginFilter.setAuthenticationFailureHandler(failureHandler);
        List<IAuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
        if (!this.authenticationConverters.isEmpty()) {
            authenticationConverters.addAll(0, this.authenticationConverters);
        }
        formLoginFilter.setAuthenticationConverter(
                new DelegatingAuthTypeConverter(defaultConverter,authenticationConverters));
        http.addFilterBefore(formLoginFilter, UsernamePasswordAuthenticationFilter.class);
        authenticationProviders.forEach(provider -> {
            http.authenticationProvider(provider);
        });
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            formLoginFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            formLoginFilter.setRememberMeServices(rememberMeServices);
        }
        var securityContextHolderStrategy = getSecurityContextHolderStrategy();
        formLoginFilter.setSecurityContextHolderStrategy(securityContextHolderStrategy);
    }

    SecurityContextRepository getSecurityContextRepository() {
        SecurityContextRepository securityContextRepository = getBuilder()
                .getSharedObject(SecurityContextRepository.class);
        if (securityContextRepository == null) {
            securityContextRepository = new DelegatingSecurityContextRepository(
                    new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());
        }
        return securityContextRepository;
    }

    private List<IAuthenticationConverter> createDefaultAuthenticationConverters() {
        List<IAuthenticationConverter> authenticationConverters = new ArrayList<>();

        return authenticationConverters;
    }

    public FormLoginConfigurer authenticationConverter(IAuthenticationConverter converter) {
        authenticationConverters.add(converter);
        return this;
    }

    public FormLoginConfigurer authenticationProvider(AuthenticationProvider provider) {
        authenticationProviders.add(provider);
        return this;
    }

    public FormLoginConfigurer successHandler(AuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
        return this;
    }

    public FormLoginConfigurer failureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
        return this;
    }

    public FormLoginConfigurer defaultAuthenticationConverter(Class<? extends IAuthenticationConverter> clazz) {
        Assert.notNull(clazz, "authenticationConverter cannot be null");
        CjAuthConverter authType = clazz.getAnnotation(CjAuthConverter.class);
        this.defaultConverter = authType == null ? "password" : authType.value();
        return this;
    }

    public FormLoginConfigurer loginPage(String loginPage) {
        Assert.notNull(loginPage, "loginPage cannot be null");
        this.loginPage=loginPage;
        return this;
    }
}
