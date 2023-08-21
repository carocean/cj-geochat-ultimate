package cj.geochat.ability.oauth.server.entrypoint.verifycode.resolver;

import cj.geochat.ability.oauth.server.entrypoint.verifycode.IVerifyCodeRequestResolver;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeInfo;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeRequest;
import cj.geochat.ability.oauth.server.annotation.CjVerifyType;
import com.github.f4b6a3.ulid.UlidCreator;
import jakarta.servlet.http.HttpServletRequest;

@CjVerifyType("guest_code")
public class GuestVerifyCodeRequestResolver implements IVerifyCodeRequestResolver {
    @Override
    public VerifyCodeRequest resolve(HttpServletRequest request) {
        VerifyCodeRequest vcr = new VerifyCodeInfo();
        vcr.setPrincipal(UlidCreator.getUlid().toLowerCase());
        vcr.setVerifyType("guest_code");
        return vcr;
    }
}
