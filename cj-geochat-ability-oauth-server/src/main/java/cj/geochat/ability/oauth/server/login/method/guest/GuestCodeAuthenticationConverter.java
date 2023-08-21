package cj.geochat.ability.oauth.server.login.method.guest;

import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import cj.geochat.ability.oauth.server.login.method.sms.SmsCodeAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;

@CjAuthConverter("guest_code")
public class GuestCodeAuthenticationConverter implements IAuthenticationConverter {
    private String principalParameter = "guest"; //对应当事人，是临时账号
    private String credentialsParameter = "code"; //对应验证码
    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {
        String principal = this.obtainPrincipal(request);
        principal = principal != null ? principal : "";
        principal = principal.trim();
        String code = this.obtainCredentials(request);
        code = code != null ? code : "";

        GuestCodeAuthenticationToken authRequest = new GuestCodeAuthenticationToken(principal, code);
        return authRequest;
    }
    protected String obtainCredentials(HttpServletRequest request) {
        return request.getParameter(this.credentialsParameter);
    }

    protected String obtainPrincipal(HttpServletRequest request) {
        return request.getParameter(this.principalParameter);
    }
}
