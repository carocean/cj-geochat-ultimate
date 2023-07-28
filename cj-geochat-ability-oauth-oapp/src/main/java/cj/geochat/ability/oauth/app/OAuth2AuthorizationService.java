package cj.geochat.ability.oauth.app;

import org.springframework.security.core.Authentication;

public interface OAuth2AuthorizationService {

	Authentication findByToken(String token, Object details) throws Throwable;

}