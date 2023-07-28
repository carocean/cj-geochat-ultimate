package cj.geochat.ability.oauth.server.filter;

import cj.geochat.ability.oauth.server.convert.DelegatingAuthTypeConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


/**
 * 登录过滤器
 */
public class FormLoginFilter extends AbstractAuthenticationProcessingFilter {


    private boolean postOnly = true;

    IAuthenticationConverter converter;


    public FormLoginFilter(AntPathRequestMatcher antPathRequestMatcher,AuthenticationManager authenticationManager) {
        super(antPathRequestMatcher, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (this.postOnly && !"POST".equals(request.getMethod())) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }
        AbstractAuthenticationToken authRequest = converter.convert(request);
        this.setDetails(request, authRequest);
        // 认证
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    protected void setDetails(HttpServletRequest request, AbstractAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }


    public void setAuthenticationConverter(DelegatingAuthTypeConverter delegatingAuthTypeConverter) {
        this.converter = delegatingAuthTypeConverter;
    }
}
