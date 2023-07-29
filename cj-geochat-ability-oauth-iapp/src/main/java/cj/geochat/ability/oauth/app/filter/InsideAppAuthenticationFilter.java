package cj.geochat.ability.oauth.app.filter;

import cj.geochat.ability.oauth.app.TokenExtractor;
import cj.geochat.ability.oauth.app.entrypoint.InsideAppAuthenticationEntryPoint;
import cj.geochat.ability.oauth.app.resolver.DefaultTokenExtractor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class InsideAppAuthenticationFilter extends OncePerRequestFilter {
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private AuthenticationEntryPoint authenticationEntryPoint = new InsideAppAuthenticationEntryPoint();
    private AuthenticationFailureHandler authenticationFailureHandler = new AuthenticationEntryPointFailureHandler((request, response, exception) -> {
        this.authenticationEntryPoint.commence(request, response, exception);
    });
    private TokenExtractor tokenExtractor = new DefaultTokenExtractor();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private AuthenticationManager authenticationManager;

    public InsideAppAuthenticationFilter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authRequest;
        try {
            authRequest = this.tokenExtractor.resolve(request);
        } catch (AuthenticationException var10) {
            this.logger.trace("Sending to authentication entry point since failed to resolve bearer token", var10);
            this.authenticationEntryPoint.commence(request, response, var10);
            return;
        }

        if (authRequest == null) {
            this.logger.trace("Did not process request since did not find bearer token");
            filterChain.doFilter(request, response);
        } else {
            try {
                Authentication authenticationResult = authenticationManager.authenticate(authRequest);
                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authenticationResult);
                this.securityContextHolderStrategy.setContext(context);
                this.securityContextRepository.saveContext(context, request, response);
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authenticationResult));
                }

                filterChain.doFilter(request, response);
            } catch (AuthenticationException var9) {
                this.securityContextHolderStrategy.clearContext();
                this.logger.trace("Failed to process authentication request", var9);
                this.authenticationFailureHandler.onAuthenticationFailure(request, response, var9);
            }

        }
    }

    public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
        Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
        this.securityContextHolderStrategy = securityContextHolderStrategy;
    }

    public void setSecurityContextRepository(SecurityContextRepository securityContextRepository) {
        Assert.notNull(securityContextRepository, "securityContextRepository cannot be null");
        this.securityContextRepository = securityContextRepository;
    }

    public void setTokenExtractor(TokenExtractor tokenExtractor) {
        Assert.notNull(tokenExtractor, "bearerTokenResolver cannot be null");
        this.tokenExtractor = tokenExtractor;
    }

    public void setAuthenticationEntryPoint(final AuthenticationEntryPoint authenticationEntryPoint) {
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    public void setAuthenticationFailureHandler(final AuthenticationFailureHandler authenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }
}
