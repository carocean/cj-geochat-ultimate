package cj.geochat.ability.oauth.server.entrypoint.verifycode;

import jakarta.servlet.http.HttpServletRequest;

public interface IVerifyCodeRequestResolver {
    VerifyCodeRequest resolve(HttpServletRequest request);

}
