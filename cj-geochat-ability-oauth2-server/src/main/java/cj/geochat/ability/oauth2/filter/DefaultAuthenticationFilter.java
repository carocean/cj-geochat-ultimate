package cj.geochat.ability.oauth2.filter;

import cj.geochat.ability.oauth2.grant.IGrantTypeAuthenticationFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class DefaultAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/login", "POST");
    private boolean postOnly = true;

    public DefaultAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }
    IGrantTypeAuthenticationFactory factory;
    public DefaultAuthenticationFilter(AuthenticationManager authenticationManager,IGrantTypeAuthenticationFactory factory) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
        this.factory=factory;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        if (this.postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        AbstractAuthenticationToken authRequest = factory.extractAuthenticationToken(request);
        if (authRequest == null) {
            //默认系统的认证逻辑
            String username = request.getParameter("username");
            username = username != null ? username : "";
            username = username.trim();
            String password = request.getParameter("password");
            password = password != null ? password : "";
            authRequest = new UsernamePasswordAuthenticationToken(username, password);
        }
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
        return this.getAuthenticationManager().authenticate(authRequest);
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }


}
