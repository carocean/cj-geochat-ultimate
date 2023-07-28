package cj.geochat.ability.oauth.app;


import jakarta.servlet.http.HttpServletRequest;

@FunctionalInterface
public interface BearerTokenResolver {
    String resolve(HttpServletRequest request);
}