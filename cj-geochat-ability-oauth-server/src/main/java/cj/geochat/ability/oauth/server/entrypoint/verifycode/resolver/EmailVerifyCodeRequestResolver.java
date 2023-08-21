package cj.geochat.ability.oauth.server.entrypoint.verifycode.resolver;

import cj.geochat.ability.oauth.server.entrypoint.verifycode.IVerifyCodeRequestResolver;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeInfo;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeRequest;
import cj.geochat.ability.oauth.server.annotation.CjVerifyType;
import com.github.f4b6a3.ulid.UlidCreator;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

@CjVerifyType("email_code")
public class EmailVerifyCodeRequestResolver implements IVerifyCodeRequestResolver {
    @Override
    public VerifyCodeRequest resolve(HttpServletRequest request) {
        String principal = request.getParameter("email");
        if (!StringUtils.hasLength(principal)) {
            return null;
        }
        VerifyCodeRequest vcr = new VerifyCodeInfo();
        vcr.setPrincipal(principal);
        vcr.setVerifyType("email_code");
        return vcr;
    }
}
