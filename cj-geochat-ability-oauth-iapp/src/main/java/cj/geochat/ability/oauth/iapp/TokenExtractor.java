package cj.geochat.ability.oauth.iapp;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

@FunctionalInterface
public interface TokenExtractor {
    Authentication resolve(HttpServletRequest request);
}