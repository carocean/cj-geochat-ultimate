package cj.geochat.ability.oauth.server.login.method.sms;

import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import cj.geochat.ability.oauth.server.convert.IAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;

@CjAuthConverter("sms_code")
public class SmsCodeAuthenticationConverter implements IAuthenticationConverter {
    private String principalParameter = "phone"; //对应手机号
    private String credentialsParameter = "code"; //对应验证码
    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {
        String phone = this.obtainPrincipal(request);
        phone = phone != null ? phone : "";
        phone = phone.trim();
        String code = this.obtainCredentials(request);
        code = code != null ? code : "";

        SmsCodeAuthenticationToken authRequest = new SmsCodeAuthenticationToken(phone, code);
        return authRequest;
    }
    protected String obtainCredentials(HttpServletRequest request) {
        return request.getParameter(this.credentialsParameter);
    }

    protected String obtainPrincipal(HttpServletRequest request) {
        return request.getParameter(this.principalParameter);
    }
}
