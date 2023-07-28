package cj.geochat.ability.oauth.server.login.method.password;

import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;

@CjAuthConverter("password")
public class PasswordAuthenticationConverter implements IAuthenticationConverter {
    private String principalParameter = "username"; //对应手机号
    private String credentialsParameter = "password"; //对应验证码
    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {
        String username = this.obtainPrincipal(request);
        username = username != null ? username : "";
        username = username.trim();
        String password = this.obtainCredentials(request);
        password = password != null ? password : "";

        PasswordAuthenticationToken authRequest = new PasswordAuthenticationToken(username, password);
        return authRequest;
    }
    protected String obtainCredentials(HttpServletRequest request) {
        return request.getParameter(this.credentialsParameter);
    }

    protected String obtainPrincipal(HttpServletRequest request) {
        return request.getParameter(this.principalParameter);
    }
}
