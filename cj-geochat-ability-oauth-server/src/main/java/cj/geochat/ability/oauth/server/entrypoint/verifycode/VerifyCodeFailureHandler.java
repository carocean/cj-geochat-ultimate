package cj.geochat.ability.oauth.server.entrypoint.verifycode;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;

import java.io.IOException;

public interface VerifyCodeFailureHandler {
    void onVerifyCodeFailure(HttpServletRequest request, HttpServletResponse response,
                                 AuthenticationException exception) throws IOException, ServletException;
}
