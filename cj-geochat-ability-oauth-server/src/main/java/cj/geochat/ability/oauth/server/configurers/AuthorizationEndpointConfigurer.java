package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.OAuth2AuthorizationCode;
import cj.geochat.ability.oauth.server.entrypoint.authorize.consent.OAuth2AuthorizationConsentAuthenticationProvider;
import cj.geochat.ability.oauth.server.entrypoint.authorize.request.OAuth2AuthorizationCodeRequestAuthenticationProvider;
import cj.geochat.ability.oauth.server.convert.DelegatingResponseTypeConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.filter.OAuth2AuthorizationEndpointFilter;
import cj.geochat.ability.oauth.server.repository.RegisteredAppRepository;
import cj.geochat.ability.oauth.server.generator.OAuth2AuthorizationCodeGenerator;
import cj.geochat.ability.oauth.server.service.InMemoryOAuth2AuthorizationConsentService;
import cj.geochat.ability.oauth.server.service.InMemoryOAuth2AuthorizationService;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationConsentService;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.server.generator.OAuth2TokenGenerator;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import cj.geochat.ability.oauth.server.util.SecurityBeanUtil;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.util.ArrayList;
import java.util.List;

public class AuthorizationEndpointConfigurer extends AbstractHttpConfigurer<AuthorizationEndpointConfigurer, HttpSecurity> {
    private final List<IAuthenticationConverter> authenticationConverters = new ArrayList<>();
    private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
    private RegisteredAppRepository registeredAppRepository;
    private OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator;
    private OAuth2AuthorizationConsentService authorizationConsentService;
    private OAuth2AuthorizationService authorizationService;


    @Override
    public void init(HttpSecurity builder) throws Exception {
        setBuilder(builder);
        initService(builder);
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        AuthorizationServerSettings authorizationServerSettings = getAuthorizationServerSettings(httpSecurity);
        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        authenticationProviders.forEach(provider -> {
            if (provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider codeRequestAuthenticationProvider) {
                configCodeRequestAuthenticationProvider(codeRequestAuthenticationProvider);
            }
            if (provider instanceof OAuth2AuthorizationConsentAuthenticationProvider consentAuthenticationProvider) {
                configConsentAuthenticationProvider(consentAuthenticationProvider);
            }
            httpSecurity.authenticationProvider(provider);
        });
        List<IAuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
        if (!this.authenticationConverters.isEmpty()) {
            authenticationConverters.addAll(0, this.authenticationConverters);
        }

        OAuth2AuthorizationEndpointFilter endpointFilter = new OAuth2AuthorizationEndpointFilter(authenticationManager, authorizationServerSettings.getAuthorizationEndpoint());
        endpointFilter.setAuthenticationConverter(
                new DelegatingResponseTypeConverter("consent", authenticationConverters)
        );
        httpSecurity.addFilterBefore(postProcess(endpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

    }

    private void initService(HttpSecurity http) {
        if (registeredAppRepository == null) {
            registeredAppRepository = SecurityBeanUtil.getBean(http, RegisteredAppRepository.class);
        } else {
            http.setSharedObject(RegisteredAppRepository.class, this.registeredAppRepository);
        }

        if (this.authorizationService == null) {
            authorizationService = SecurityBeanUtil.getBean(http, OAuth2AuthorizationService.class, new InMemoryOAuth2AuthorizationService());
        } else {
            http.setSharedObject(OAuth2AuthorizationService.class, this.authorizationService);
        }

        if (this.authorizationConsentService == null) {
            authorizationConsentService = SecurityBeanUtil.getBean(http, OAuth2AuthorizationConsentService.class, new InMemoryOAuth2AuthorizationConsentService());
        } else {
            http.setSharedObject(OAuth2AuthorizationConsentService.class, this.authorizationConsentService);
        }

        if (this.authorizationCodeGenerator == null) {
            authorizationCodeGenerator = SecurityBeanUtil.getBean(http, OAuth2AuthorizationCodeGenerator.class, new OAuth2AuthorizationCodeGenerator());
        }else {
            http.setSharedObject(OAuth2AuthorizationCodeGenerator.class,(OAuth2AuthorizationCodeGenerator) this.authorizationCodeGenerator);
        }
    }

    private void configConsentAuthenticationProvider(OAuth2AuthorizationConsentAuthenticationProvider provider) {
        provider.setRegisteredAppRepository(registeredAppRepository);
        provider.setAuthorizationService(authorizationService);
        provider.setAuthorizationConsentService(authorizationConsentService);
        provider.setAuthorizationCodeGenerator(authorizationCodeGenerator);
    }

    private void configCodeRequestAuthenticationProvider(OAuth2AuthorizationCodeRequestAuthenticationProvider provider) {
        provider.setRegisteredAppRepository(registeredAppRepository);
        provider.setAuthorizationService(authorizationService);
        provider.setAuthorizationConsentService(authorizationConsentService);
        provider.setAuthorizationCodeGenerator(authorizationCodeGenerator);
    }

    private List<IAuthenticationConverter> createDefaultAuthenticationConverters() {
        List<IAuthenticationConverter> authenticationConverters = new ArrayList<>();

        return authenticationConverters;
    }

    AuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
        AuthorizationServerSettings authorizationServerSettings = httpSecurity.getSharedObject(AuthorizationServerSettings.class);
        if (authorizationServerSettings == null) {
            authorizationServerSettings = httpSecurity.getSharedObject(ApplicationContext.class).getBean(AuthorizationServerSettings.class);
            httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        }
        return authorizationServerSettings;
    }

    public AuthorizationEndpointConfigurer authenticationConverter(IAuthenticationConverter converter) {
        authenticationConverters.add(converter);
        return this;
    }

    public AuthorizationEndpointConfigurer authenticationProvider(AuthenticationProvider provider) {
        authenticationProviders.add(provider);
        return this;
    }

    public AuthorizationEndpointConfigurer registeredAppRepository(RegisteredAppRepository registeredAppRepository) {
        this.registeredAppRepository = registeredAppRepository;
        return this;
    }

    public AuthorizationEndpointConfigurer authorizationCodeGenerator(OAuth2TokenGenerator<OAuth2AuthorizationCode> authorizationCodeGenerator) {
        this.authorizationCodeGenerator = authorizationCodeGenerator;
        return this;
    }

    public AuthorizationEndpointConfigurer authorizationConsentService(OAuth2AuthorizationConsentService authorizationConsentService) {
        this.authorizationConsentService = authorizationConsentService;
        return this;
    }

    public AuthorizationEndpointConfigurer authorizationService(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
        return this;
    }
}
