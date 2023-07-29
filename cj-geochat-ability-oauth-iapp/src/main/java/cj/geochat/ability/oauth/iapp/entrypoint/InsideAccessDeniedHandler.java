package cj.geochat.ability.oauth.iapp.entrypoint;

import cj.geochat.ability.oauth.iapp.resolver.AbstractOAuth2TokenAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

public final class InsideAccessDeniedHandler implements AccessDeniedHandler {
    private String realmName;

    public InsideAccessDeniedHandler() {
    }

    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) {
        Map<String, String> parameters = new LinkedHashMap();
        if (this.realmName != null) {
            parameters.put("realm", this.realmName);
        }

        if (request.getUserPrincipal() instanceof AbstractOAuth2TokenAuthenticationToken) {
            parameters.put("error", "insufficient_scope");
            parameters.put("error_description", "The request requires higher privileges than provided by the access token.");
            parameters.put("error_uri", "https://tools.ietf.org/html/rfc6750#section-3.1");
        }

        String wwwAuthenticate = computeWWWAuthenticateHeaderValue(parameters);
        response.addHeader("WWW-Authenticate", wwwAuthenticate);
        response.setStatus(HttpStatus.FORBIDDEN.value());
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
