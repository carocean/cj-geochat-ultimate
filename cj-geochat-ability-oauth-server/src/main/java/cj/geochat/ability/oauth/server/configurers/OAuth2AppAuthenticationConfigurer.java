package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.OAuth2ConfigurerUtils;
import cj.geochat.ability.oauth.server.convert.DelegatingAuthMethodConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.app.*;
import cj.geochat.ability.oauth.server.filter.OAuth2AppAuthenticationFilter;
import cj.geochat.ability.oauth.server.repository.RegisteredAppRepository;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;

public class OAuth2AppAuthenticationConfigurer extends AbstractHttpConfigurer<OAuth2AppAuthenticationConfigurer, HttpSecurity> {
    private RequestMatcher requestMatcher;
    private final List<IAuthenticationConverter> authenticationConverters = new ArrayList<>();
    private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(
                        authorizationServerSettings.getTokenEndpoint(),
                        HttpMethod.POST.name())
                );

        List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
        if (!this.authenticationProviders.isEmpty()) {
            authenticationProviders.addAll(0, this.authenticationProviders);
        }

        authenticationProviders.forEach(authenticationProvider ->
                httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        OAuth2AppAuthenticationFilter clientAuthenticationFilter = new OAuth2AppAuthenticationFilter(
                authenticationManager, this.requestMatcher);
        List<IAuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
        if (!this.authenticationConverters.isEmpty()) {
            authenticationConverters.addAll(this.authenticationConverters);
        }
        clientAuthenticationFilter.setAuthenticationConverter(
                new DelegatingAuthMethodConverter("app_secret_post",authenticationConverters));
//        if (this.authenticationSuccessHandler != null) {
//            clientAuthenticationFilter.setAuthenticationSuccessHandler(this.authenticationSuccessHandler);
//        }
//        if (this.errorResponseHandler != null) {
//            clientAuthenticationFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
//        }
        httpSecurity.addFilterAfter(postProcess(clientAuthenticationFilter), AbstractPreAuthenticatedProcessingFilter.class);
    }

    public OAuth2AppAuthenticationConfigurer authenticationConverter(IAuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverters.add(authenticationConverter);
        return this;
    }

    public OAuth2AppAuthenticationConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
        Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    private static List<IAuthenticationConverter> createDefaultAuthenticationConverters() {
        List<IAuthenticationConverter> authenticationConverters = new ArrayList<>();

        authenticationConverters.add(new AppSecretBasicAuthenticationConverter());
        authenticationConverters.add(new AppSecretPostAuthenticationConverter());
        authenticationConverters.add(new PublicAppAuthenticationConverter());

        return authenticationConverters;
    }
    private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        RegisteredAppRepository registeredClientRepository = OAuth2ConfigurerUtils.getRegisteredClientRepository(httpSecurity);
        OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity);

        AppSecretAuthenticationProvider appSecretAuthenticationProvider =
                new AppSecretAuthenticationProvider(registeredClientRepository, authorizationService);
        PasswordEncoder passwordEncoder = OAuth2ConfigurerUtils.getOptionalBean(httpSecurity, PasswordEncoder.class);
        if (passwordEncoder != null) {
            appSecretAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        }
        authenticationProviders.add(appSecretAuthenticationProvider);

        PublicAppAuthenticationProvider publicAppAuthenticationProvider =
                new PublicAppAuthenticationProvider(registeredClientRepository, authorizationService);
        authenticationProviders.add(publicAppAuthenticationProvider);

        return authenticationProviders;
    }

}
