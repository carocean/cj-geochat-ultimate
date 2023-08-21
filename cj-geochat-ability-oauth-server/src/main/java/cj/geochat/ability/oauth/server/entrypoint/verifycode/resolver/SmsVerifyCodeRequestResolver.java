package cj.geochat.ability.oauth.server.entrypoint.verifycode.resolver;

import cj.geochat.ability.oauth.server.entrypoint.verifycode.IVerifyCodeRequestResolver;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeInfo;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeRequest;
import cj.geochat.ability.oauth.server.annotation.CjVerifyType;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

@CjVerifyType("sms_code")
public class SmsVerifyCodeRequestResolver implements IVerifyCodeRequestResolver {
    @Override
    public VerifyCodeRequest resolve(HttpServletRequest request) {
        String principal = request.getParameter("phone");
        if (!StringUtils.hasLength(principal)) {
            return null;
        }
        VerifyCodeRequest vcr = new VerifyCodeInfo();
        vcr.setPrincipal(principal);
        vcr.setVerifyType("sms_code");
        return vcr;
    }
}
