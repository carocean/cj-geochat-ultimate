package cj.geochat.ability.oauth.app.oauth2;

import cj.geochat.ability.oauth.app.BearerTokenResolver;
import cj.geochat.ability.oauth.app.OAuth2AuthorizationService;
import cj.geochat.ability.oauth.app.entrypoint.BearerTokenAccessDeniedHandler;
import cj.geochat.ability.oauth.app.entrypoint.BearerTokenAuthenticationEntryPoint;
import cj.geochat.ability.oauth.app.entrypoint.OpaqueTokenAuthenticationProvider;
import cj.geochat.ability.oauth.app.filter.BearerTokenAuthenticationFilter;
import cj.geochat.ability.oauth.app.resolver.DefaultBearerTokenResolver;
import cj.geochat.ability.oauth.app.OAuth2AuthenticationException;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.security.web.util.matcher.*;
import org.springframework.util.Assert;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class OAuth2AuthorizationOutsideAppConfigurer<H extends HttpSecurityBuilder<H>> extends AbstractHttpConfigurer<OAuth2AuthorizationOutsideAppConfigurer<H>, H> {

    private static final RequestHeaderRequestMatcher X_REQUESTED_WITH = new RequestHeaderRequestMatcher(
            "X-Requested-With", "XMLHttpRequest");

    private final ApplicationContext context;

    private AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;

    private BearerTokenResolver bearerTokenResolver;


    private OpaqueTokenConfigurer opaqueTokenConfigurer;

    private AccessDeniedHandler accessDeniedHandler = new DelegatingAccessDeniedHandler(
            new LinkedHashMap<>(Map.of(CsrfException.class, new AccessDeniedHandlerImpl())),
            new BearerTokenAccessDeniedHandler());

    private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();

    private BearerTokenRequestMatcher requestMatcher = new BearerTokenRequestMatcher();
    private OAuth2AuthorizationService authorizationService;

    public OAuth2AuthorizationOutsideAppConfigurer(ApplicationContext context) {
        Assert.notNull(context, "context cannot be null");
        this.context = context;
    }

    public OAuth2AuthorizationOutsideAppConfigurer<H> accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    public OAuth2AuthorizationOutsideAppConfigurer<H> authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
        Assert.notNull(entryPoint, "entryPoint cannot be null");
        this.authenticationEntryPoint = entryPoint;
        return this;
    }

    public OAuth2AuthorizationOutsideAppConfigurer<H> authenticationManagerResolver(
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
        Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
        this.authenticationManagerResolver = authenticationManagerResolver;
        return this;
    }

    public OAuth2AuthorizationOutsideAppConfigurer<H> bearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
        Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
        this.bearerTokenResolver = bearerTokenResolver;
        return this;
    }

    void registerService(H http) {
        if (authorizationService == null) {
            authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
        }
        if (authorizationService == null) {
            ApplicationContext ctx = http.getSharedObject(ApplicationContext.class);
            authorizationService = ctx.getBean(OAuth2AuthorizationService.class);
        }
    }

    @Override
    public void init(H http) {
        validateConfiguration();
        registerService(http);
        registerDefaultAccessDeniedHandler(http);
        registerDefaultEntryPoint(http);
        registerDefaultCsrfOverride(http);
        AuthenticationProvider authenticationProvider = getAuthenticationProvider();
        if (authenticationProvider != null) {
            http.authenticationProvider(authenticationProvider);
        }
    }

    @Override
    public void configure(H http) {
        BearerTokenResolver bearerTokenResolver = getBearerTokenResolver();
        this.requestMatcher.setBearerTokenResolver(bearerTokenResolver);
        AuthenticationManager authenticationManager = getAuthenticationManager(http);

        BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(authenticationManager);
        filter.setBearerTokenResolver(bearerTokenResolver);
        filter.setAuthenticationEntryPoint(this.authenticationEntryPoint);
        filter.setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());
        filter = postProcess(filter);
        http.addFilterBefore(filter, RequestCacheAwareFilter.class);
    }


    public OAuth2AuthorizationOutsideAppConfigurer<H> opaqueToken(Customizer<OpaqueTokenConfigurer> opaqueTokenCustomizer) {
        if (this.opaqueTokenConfigurer == null) {
            this.opaqueTokenConfigurer = new OpaqueTokenConfigurer(this.context);
        }
        opaqueTokenCustomizer.customize(this.opaqueTokenConfigurer);
        return this;
    }

    private void validateConfiguration() {
        if (this.authenticationManagerResolver == null) {
            Assert.state(this.opaqueTokenConfigurer != null,
                    " Opaque Tokens via "
                            + "http.oauth2ResourceServer().opaqueToken().");
        } else {
            Assert.state(this.opaqueTokenConfigurer == null,
                    "If an authenticationManagerResolver() is configured, then it takes "
                            + "precedence over any jwt() or opaqueToken() configuration.");
        }
    }

    private void registerDefaultAccessDeniedHandler(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAccessDeniedHandlerFor(this.accessDeniedHandler, this.requestMatcher);
        }
    }

    private void registerDefaultEntryPoint(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            ContentNegotiationStrategy contentNegotiationStrategy = http
                    .getSharedObject(ContentNegotiationStrategy.class);
            if (contentNegotiationStrategy == null) {
                contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
            }
            MediaTypeRequestMatcher restMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
                    MediaType.APPLICATION_ATOM_XML, MediaType.APPLICATION_FORM_URLENCODED, MediaType.APPLICATION_JSON,
                    MediaType.APPLICATION_OCTET_STREAM, MediaType.APPLICATION_XML, MediaType.MULTIPART_FORM_DATA,
                    MediaType.TEXT_XML);
            restMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
            MediaTypeRequestMatcher allMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.ALL);
            allMatcher.setUseEquals(true);
            RequestMatcher notHtmlMatcher = new NegatedRequestMatcher(
                    new MediaTypeRequestMatcher(contentNegotiationStrategy, MediaType.TEXT_HTML));
            RequestMatcher restNotHtmlMatcher = new AndRequestMatcher(
                    Arrays.<RequestMatcher>asList(notHtmlMatcher, restMatcher));
            RequestMatcher preferredMatcher = new OrRequestMatcher(
                    Arrays.asList(this.requestMatcher, X_REQUESTED_WITH, restNotHtmlMatcher, allMatcher));
            exceptionHandling.defaultAuthenticationEntryPointFor(this.authenticationEntryPoint, preferredMatcher);
        }
    }

    private void registerDefaultCsrfOverride(H http) {
        CsrfConfigurer<H> csrf = http.getConfigurer(CsrfConfigurer.class);
        if (csrf != null) {
            csrf.ignoringRequestMatchers(this.requestMatcher);
        }
    }

    AuthenticationProvider getAuthenticationProvider() {
        if (this.opaqueTokenConfigurer != null) {
            return this.opaqueTokenConfigurer.getAuthenticationProvider();
        }
        return null;
    }

    AuthenticationManager getAuthenticationManager(H http) {
        if (this.opaqueTokenConfigurer != null) {
            return this.opaqueTokenConfigurer.getAuthenticationManager(http);
        }
        return http.getSharedObject(AuthenticationManager.class);
    }

    BearerTokenResolver getBearerTokenResolver() {
        if (this.bearerTokenResolver == null) {
            if (this.context.getBeanNamesForType(BearerTokenResolver.class).length > 0) {
                this.bearerTokenResolver = this.context.getBean(BearerTokenResolver.class);
            } else {
                this.bearerTokenResolver = new DefaultBearerTokenResolver();
            }
        }
        return this.bearerTokenResolver;
    }

    public OAuth2AuthorizationOutsideAppConfigurer authorizationService(OAuth2AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
        return this;
    }


    public class OpaqueTokenConfigurer {

        private final ApplicationContext context;

        private AuthenticationManager authenticationManager;

        OpaqueTokenConfigurer(ApplicationContext context) {
            this.context = context;
        }

        public OpaqueTokenConfigurer authenticationManager(AuthenticationManager authenticationManager) {
            Assert.notNull(authenticationManager, "authenticationManager cannot be null");
            this.authenticationManager = authenticationManager;
            return this;
        }

        AuthenticationProvider getAuthenticationProvider() {
            if (this.authenticationManager != null) {
                return null;
            }
            OpaqueTokenAuthenticationProvider opaqueTokenAuthenticationProvider = new OpaqueTokenAuthenticationProvider(authorizationService);
//            OpaqueTokenAuthenticationConverter authenticationConverter = getAuthenticationConverter();
//            if (authenticationConverter != null) {
//                opaqueTokenAuthenticationProvider.setAuthenticationConverter(authenticationConverter);
//            }
            return opaqueTokenAuthenticationProvider;
        }

        AuthenticationManager getAuthenticationManager(H http) {
            if (this.authenticationManager != null) {
                return this.authenticationManager;
            }
            return http.getSharedObject(AuthenticationManager.class);
        }

    }

    private static final class BearerTokenRequestMatcher implements RequestMatcher {

        private BearerTokenResolver bearerTokenResolver;

        @Override
        public boolean matches(HttpServletRequest request) {
            try {
                return this.bearerTokenResolver.resolve(request) != null;
            } catch (OAuth2AuthenticationException ex) {
                return false;
            }
        }

        void setBearerTokenResolver(BearerTokenResolver tokenResolver) {
            Assert.notNull(tokenResolver, "resolver cannot be null");
            this.bearerTokenResolver = tokenResolver;
        }

    }
}
