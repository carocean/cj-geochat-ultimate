package cj.geochat.ability.oauth.server.oauth2;

import cj.geochat.ability.oauth.server.configurers.FormLoginConfigurer;
import cj.geochat.ability.oauth.server.configurers.Oauth2ServerConfigurer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.Map;

public class OAuth2AuthorizationServerConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private RequestMatcher endpointsMatcher;


    private final Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>, SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = createConfigurers();

    /**
     * Returns a {@link RequestMatcher} for the authorization server endpoints.
     *
     * @return a {@link RequestMatcher} for the authorization server endpoints
     */
    public RequestMatcher getEndpointsMatcher() {
        // Return a deferred RequestMatcher
        // since endpointsMatcher is constructed in init(HttpSecurity).
        return (request) -> this.endpointsMatcher.matches(request);
    }

    @Override
    public void setBuilder(HttpSecurity builder) {
        super.setBuilder(builder);
        this.configurers.values().stream().forEach(e -> {
            e.setBuilder(builder);
        });
    }

    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        this.configurers.values().forEach(configurer -> {
            configurer.addObjectPostProcessor(this::postProcess);
            try {
                configurer.init(httpSecurity);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public void configure(HttpSecurity httpSecurity) {
        this.configurers.values().forEach(configurer -> {
            try {
                configurer.configure(httpSecurity);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });

    }

    public OAuth2AuthorizationServerConfigurer formLogin(Customizer<FormLoginConfigurer> authAuthenticationCustomizer) {
        authAuthenticationCustomizer.customize(getConfigurer(FormLoginConfigurer.class));
        return this;
    }

    public OAuth2AuthorizationServerConfigurer oauth2Server(Customizer<Oauth2ServerConfigurer> oauth2ServerConfigurerCustomizer) {
        oauth2ServerConfigurerCustomizer.customize(getConfigurer(Oauth2ServerConfigurer.class));
        return this;
    }

    private Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>, SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> createConfigurers() {
        Map<Class<? extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>>, SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity>> configurers = new LinkedHashMap<>();
        configurers.put(FormLoginConfigurer.class, new FormLoginConfigurer());
        configurers.put(Oauth2ServerConfigurer.class, new Oauth2ServerConfigurer());
        return configurers;
    }

    @SuppressWarnings("unchecked")
    private <T> T getConfigurer(Class<T> type) {
        return (T) this.configurers.get(type);
    }
}
