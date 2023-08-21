package cj.geochat.ability.oauth.server.configurers;

import cj.geochat.ability.oauth.server.OAuth2ConfigurerUtils;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.*;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.provider.GuestVerifyCodeProvider;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.resolver.EmailVerifyCodeRequestResolver;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.resolver.GuestVerifyCodeRequestResolver;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.resolver.SmsVerifyCodeRequestResolver;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.service.DefaultVerifyCodeService;
import cj.geochat.ability.oauth.server.filter.OAuth2VerificationCodeEndpointFilter;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import cj.geochat.ability.oauth.server.util.SecurityBeanUtil;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.Arrays;

public class VerificationCodeEndpointConfigurer extends AbstractHttpConfigurer<CheckTokenEndpointConfigurer, HttpSecurity> {
    private DelegatingVerifyCodeProvider verifyCodeProvider;
    private DelegatingVerifyCodeRequestResolver verifyCodeRequestResolver;
    private IVerifyCodeService verifyCodeService;
    private VerifyCodeSuccessHandler verifyCodeSuccessHandler;
    private VerifyCodeFailureHandler verifyCodeFailureHandler;

    @Override
    public void init(HttpSecurity http) throws Exception {
        verifyCodeRequestResolver = new DelegatingVerifyCodeRequestResolver(
                Arrays.asList(
                        new GuestVerifyCodeRequestResolver(),
                        new EmailVerifyCodeRequestResolver(),
                        new SmsVerifyCodeRequestResolver()
                )
        );
        var resolvers = SecurityBeanUtil.getContext(http).getBeansOfType(IVerifyCodeRequestResolver.class).values();
        for (IVerifyCodeRequestResolver resolver : resolvers) {
            if (verifyCodeRequestResolver.containsValue(resolver.getClass())) {
                continue;
            }
            verifyCodeRequestResolver.add(resolver);
        }

        verifyCodeProvider = new DelegatingVerifyCodeProvider(Arrays.asList(
                new GuestVerifyCodeProvider()
        ));
        var providers = SecurityBeanUtil.getContext(http).getBeansOfType(IVerifyCodeProvider.class).values();
        for (IVerifyCodeProvider provider : providers) {
            if (verifyCodeProvider.contains(provider.getClass())) {
                continue;
            }
            verifyCodeProvider.add(provider);
        }

        if (verifyCodeService == null) {
            verifyCodeService = SecurityBeanUtil.getBean(http, IVerifyCodeService.class, new DefaultVerifyCodeService());
        }
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthorizationServerSettings authorizationServerSettings = OAuth2ConfigurerUtils.getAuthorizationServerSettings(http);
        OAuth2VerificationCodeEndpointFilter filter = new OAuth2VerificationCodeEndpointFilter(authorizationServerSettings.getVerificationCodeEndpoint());

        filter.setVerifyCodeRequestResolver(verifyCodeRequestResolver);

        filter.setVerifyCodeProvider(verifyCodeProvider);

        filter.setVerifyCodeService(verifyCodeService);

        if (verifyCodeFailureHandler != null) {
            filter.setVerifyCodeFailureHandler(verifyCodeFailureHandler);
        }
        if (verifyCodeSuccessHandler != null) {
            filter.setVerifyCodeSuccessHandler(verifyCodeSuccessHandler);
        }
        http.addFilterBefore(postProcess(filter), UsernamePasswordAuthenticationFilter.class);
    }

    public VerificationCodeEndpointConfigurer verifyCodeProvider(IVerifyCodeProvider verifyCodeProvider) {
        this.verifyCodeProvider.add(verifyCodeProvider);
        return this;
    }

    public VerificationCodeEndpointConfigurer verifyCodeRequestResolver(IVerifyCodeRequestResolver verifyCodeRequestResolver) {
        this.verifyCodeRequestResolver.add(verifyCodeRequestResolver);
        return this;
    }

    public VerificationCodeEndpointConfigurer verifyCodeService(IVerifyCodeService verifyCodeService) {
        this.verifyCodeService = verifyCodeService;
        return this;
    }

    public VerificationCodeEndpointConfigurer successHandler(VerifyCodeSuccessHandler verifyCodeSuccessHandler) {
        this.verifyCodeSuccessHandler = verifyCodeSuccessHandler;
        return this;
    }

    public VerificationCodeEndpointConfigurer failureHandler(VerifyCodeFailureHandler verifyCodeFailureHandler) {
        this.verifyCodeFailureHandler = verifyCodeFailureHandler;
        return this;
    }
}
