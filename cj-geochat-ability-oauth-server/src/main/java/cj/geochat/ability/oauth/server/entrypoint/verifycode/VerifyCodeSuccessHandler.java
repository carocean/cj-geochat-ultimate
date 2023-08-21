package cj.geochat.ability.oauth.server.entrypoint.verifycode;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

public interface VerifyCodeSuccessHandler {
    void onVerifyCodeSuccess(HttpServletRequest request, HttpServletResponse response,
                   VerifyCodeInfo verifyCodeInfo) throws IOException;
}
