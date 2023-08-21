package cj.geochat.ability.oauth.server.login.method.email;

import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.login.method.sms.SmsCodeAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;

@CjAuthConverter("email_code")
public class EmailCodeAuthenticationConverter implements IAuthenticationConverter {
    private String principalParameter = "email"; //邮件
    private String credentialsParameter = "code"; //对应验证码
    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {
        String email = this.obtainPrincipal(request);
        email = email != null ? email : "";
        email = email.trim();
        String code = this.obtainCredentials(request);
        code = code != null ? code : "";

        EmailCodeAuthenticationToken authRequest = new EmailCodeAuthenticationToken(email, code);
        return authRequest;
    }
    protected String obtainCredentials(HttpServletRequest request) {
        return request.getParameter(this.credentialsParameter);
    }

    protected String obtainPrincipal(HttpServletRequest request) {
        return request.getParameter(this.principalParameter);
    }
}
