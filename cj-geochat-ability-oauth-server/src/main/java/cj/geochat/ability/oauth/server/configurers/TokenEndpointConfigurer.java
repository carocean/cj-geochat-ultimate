package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.OAuth2ConfigurerUtils;
import cj.geochat.ability.oauth.server.convert.DelegatingGrantTypeConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.entrypoint.token.OAuth2AuthorizationCodeAuthenticationProvider;
import cj.geochat.ability.oauth.server.entrypoint.token.refresh.OAuth2RefreshTokenAuthenticationProvider;
import cj.geochat.ability.oauth.server.filter.OAuth2TokenEndpointFilter;
import cj.geochat.ability.oauth.server.generator.OAuth2TokenGenerator;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.List;

public class TokenEndpointConfigurer extends AbstractHttpConfigurer<TokenEndpointConfigurer, HttpSecurity> {
    private final List<IAuthenticationConverter> accessTokenRequestConverters = new ArrayList<>();
    private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
    private RequestMatcher requestMatcher;
    private OAuth2TokenGenerator tokenGenerator;

    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);
        this.requestMatcher = new AntPathRequestMatcher(
                authorizationServerSettings.getTokenEndpoint(), HttpMethod.POST.name());

        List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
        if (!this.authenticationProviders.isEmpty()) {
            authenticationProviders.addAll(this.authenticationProviders);
        }

        if (tokenGenerator == null) {
            tokenGenerator = OAuth2ConfigurerUtils.getTokenGenerator(httpSecurity);
        } else {
            getBuilder().setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
        }
        authenticationProviders.forEach(provider -> {
            if (provider instanceof OAuth2AuthorizationCodeAuthenticationProvider ocap) {
                ocap.setAuthorizationService(OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
                ocap.setTokenGenerator(tokenGenerator);
            }
            if (provider instanceof OAuth2RefreshTokenAuthenticationProvider ocap) {
                ocap.setAuthorizationService(OAuth2ConfigurerUtils.getAuthorizationService(httpSecurity));
                ocap.setTokenGenerator(tokenGenerator);
            }
            httpSecurity.authenticationProvider(postProcess(provider));
        });
    }

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {

        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(httpSecurity);

        OAuth2TokenEndpointFilter tokenEndpointFilter =
                new OAuth2TokenEndpointFilter(
                        authenticationManager,
                        authorizationServerSettings.getTokenEndpoint());
        List<IAuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();
        if (!this.accessTokenRequestConverters.isEmpty()) {
            authenticationConverters.addAll(0, this.accessTokenRequestConverters);
        }
        tokenEndpointFilter.setAuthenticationConverter(
                new DelegatingGrantTypeConverter("authorization_code", authenticationConverters));
//        if (this.accessTokenResponseHandler != null) {
//            tokenEndpointFilter.setAuthenticationSuccessHandler(this.accessTokenResponseHandler);
//        }
//        if (this.errorResponseHandler != null) {
//            tokenEndpointFilter.setAuthenticationFailureHandler(this.errorResponseHandler);
//        }
        httpSecurity.addFilterAfter(postProcess(tokenEndpointFilter), AuthorizationFilter.class);
    }

    private List<IAuthenticationConverter> createDefaultAuthenticationConverters() {
        List<IAuthenticationConverter> authenticationProviders = new ArrayList<>();

        return authenticationProviders;
    }

    private static List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        return authenticationProviders;
    }

    public TokenEndpointConfigurer authenticationConverter(IAuthenticationConverter converter) {
        this.accessTokenRequestConverters.add(converter);
        return this;
    }

    public TokenEndpointConfigurer authenticationProvider(AuthenticationProvider provider) {
        this.authenticationProviders.add(provider);
        return this;
    }

    public TokenEndpointConfigurer authorizationCodeGenerator(OAuth2TokenGenerator tokenGenerator) {
        this.tokenGenerator = tokenGenerator;
        return this;
    }
}
