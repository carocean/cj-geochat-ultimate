package cj.geochat.ability.oauth.server.filter;

import cj.geochat.ability.oauth.server.AuthorizationServerContext;
import cj.geochat.ability.oauth.server.AuthorizationServerContextHolder;
import cj.geochat.ability.oauth.server.settings.AuthorizationServerSettings;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.function.Supplier;

public class AuthorizationServerContextFilter  extends OncePerRequestFilter {
    private final AuthorizationServerSettings authorizationServerSettings;

    public AuthorizationServerContextFilter(AuthorizationServerSettings authorizationServerSettings) {
        Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
        this.authorizationServerSettings = authorizationServerSettings;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            AuthorizationServerContext authorizationServerContext =
                    new DefaultAuthorizationServerContext(
                            () -> resolveIssuer(this.authorizationServerSettings, request),
                            this.authorizationServerSettings);
            AuthorizationServerContextHolder.setContext(authorizationServerContext);
            filterChain.doFilter(request, response);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }
    }

    private static String resolveIssuer(AuthorizationServerSettings authorizationServerSettings, HttpServletRequest request) {
        return authorizationServerSettings.getIssuer() != null ?
                authorizationServerSettings.getIssuer() :
                getContextPath(request);
    }

    private static String getContextPath(HttpServletRequest request) {
        // @formatter:off
        return UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build()
                .toUriString();
        // @formatter:on
    }

    private static final class DefaultAuthorizationServerContext implements AuthorizationServerContext {
        private final Supplier<String> issuerSupplier;
        private final AuthorizationServerSettings authorizationServerSettings;

        private DefaultAuthorizationServerContext(Supplier<String> issuerSupplier, AuthorizationServerSettings authorizationServerSettings) {
            this.issuerSupplier = issuerSupplier;
            this.authorizationServerSettings = authorizationServerSettings;
        }

        @Override
        public String getIssuer() {
            return this.issuerSupplier.get();
        }

        @Override
        public AuthorizationServerSettings getAuthorizationServerSettings() {
            return this.authorizationServerSettings;
        }

    }
}
