package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.filter.AuthorizationServerContextFilter;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.util.Assert;

import java.util.LinkedHashMap;
import java.util.Map;

///参考spring oauth2 的类：OAuth2AuthorizationEndpointConfigurer
public class Oauth2ServerConfigurer extends AbstractHttpConfigurer<Oauth2ServerConfigurer, HttpSecurity> {

    private final Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>, SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = createConfigurers();


    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        this.configurers.values().forEach(configurer -> {
            configurer.setBuilder(httpSecurity);
            try {
                configurer.init(httpSecurity);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        this.configurers.values().forEach(configurer -> {
            configurer.addObjectPostProcessor(this::postProcess);
            try {
                configurer.configure(httpSecurity);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        AuthorizationServerSettings authorizationServerSettings = getAuthorizationServerSettings(httpSecurity);

        AuthorizationServerContextFilter authorizationServerContextFilter = new AuthorizationServerContextFilter(authorizationServerSettings);
        httpSecurity.addFilterAfter(postProcess(authorizationServerContextFilter), SecurityContextHolderFilter.class);

    }

    AuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
        AuthorizationServerSettings authorizationServerSettings = httpSecurity.getSharedObject(AuthorizationServerSettings.class);
        if (authorizationServerSettings == null) {
            authorizationServerSettings = httpSecurity.getSharedObject(ApplicationContext.class).getBean(AuthorizationServerSettings.class);
            httpSecurity.setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        }
        return authorizationServerSettings;
    }

    @SuppressWarnings("unchecked")
    private <T> T getConfigurer(Class<T> type) {
        return (T) this.configurers.get(type);
    }

    public Oauth2ServerConfigurer authorizationServerSettings(AuthorizationServerSettings authorizationServerSettings) {
        Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
        getBuilder().setSharedObject(AuthorizationServerSettings.class, authorizationServerSettings);
        return this;
    }

    private Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>, SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> createConfigurers() {
        Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>, SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = new LinkedHashMap<>();
        configurers.put(AuthorizationEndpointConfigurer.class, new AuthorizationEndpointConfigurer());
        configurers.put(TokenEndpointConfigurer.class, new TokenEndpointConfigurer());
        configurers.put(CheckTokenEndpointConfigurer.class, new CheckTokenEndpointConfigurer());
        configurers.put(VerificationCodeEndpointConfigurer.class, new VerificationCodeEndpointConfigurer());
        configurers.put(OAuth2AppAuthenticationConfigurer.class, new OAuth2AppAuthenticationConfigurer());
        configurers.put(LogoutEndpointConfigurer.class, new LogoutEndpointConfigurer());
        return configurers;
    }

    public Oauth2ServerConfigurer authorizationEndpoint(Customizer<AuthorizationEndpointConfigurer> authorizationEndpointConfigurerCustomizer) {
        authorizationEndpointConfigurerCustomizer.customize(getConfigurer(AuthorizationEndpointConfigurer.class));
        return this;
    }

    public Oauth2ServerConfigurer tokenEndpoint(Customizer<TokenEndpointConfigurer> tokenEndpointConfigurerCustomizer) {
        tokenEndpointConfigurerCustomizer.customize(getConfigurer(TokenEndpointConfigurer.class));
        return this;
    }

    public Oauth2ServerConfigurer appEndpoint(Customizer<OAuth2AppAuthenticationConfigurer> appAuthenticationCustomizer) {
        appAuthenticationCustomizer.customize(getConfigurer(OAuth2AppAuthenticationConfigurer.class));
        return this;
    }

    public Oauth2ServerConfigurer checkTokenEndpoint(Customizer<CheckTokenEndpointConfigurer> checkTokenEndpointConfigurerCustomizer) {
        checkTokenEndpointConfigurerCustomizer.customize(getConfigurer(CheckTokenEndpointConfigurer.class));
        return this;
    }

    public Oauth2ServerConfigurer verificationCodeEndpoint(Customizer<VerificationCodeEndpointConfigurer> verificationCodeEndpointConfigurerCustomizer) {
        verificationCodeEndpointConfigurerCustomizer.customize(getConfigurer(VerificationCodeEndpointConfigurer.class));
        return this;
    }

    public Oauth2ServerConfigurer logout(Customizer<LogoutEndpointConfigurer> logoutEndpointConfigurerCustomizer) {
        logoutEndpointConfigurerCustomizer.customize(getConfigurer(LogoutEndpointConfigurer.class));
        return this;
    }
}
