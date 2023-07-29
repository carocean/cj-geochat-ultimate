package cj.geochat.ability.oauth.app.entrypoint;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public final class InsideAppAuthenticationEntryPoint implements AuthenticationEntryPoint {
    private String realmName;

    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        Map<String, String> parameters = new LinkedHashMap();
        if (this.realmName != null) {
            parameters.put("realm", this.realmName);
        }

        String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
        response.addHeader("WWW-Authenticate", wwwAuthenticate);
        response.setStatus(status.value());
    }

    public void setRealmName(String realmName) {
        this.realmName = realmName;
    }

    private static String computeWWWAuthenticateHeaderValue(Map<String, String> parameters) {
        StringBuilder wwwAuthenticate = new StringBuilder();
        wwwAuthenticate.append("Bearer");
        if (!parameters.isEmpty()) {
            wwwAuthenticate.append(" ");
            int i = 0;

            for(Iterator var3 = parameters.entrySet().iterator(); var3.hasNext(); ++i) {
                Map.Entry<String, String> entry = (Map.Entry)var3.next();
                wwwAuthenticate.append((String)entry.getKey()).append("=\"").append((String)entry.getValue()).append("\"");
                if (i != parameters.size() - 1) {
                    wwwAuthenticate.append(", ");
                }
            }
        }

        return wwwAuthenticate.toString();
    }
}
