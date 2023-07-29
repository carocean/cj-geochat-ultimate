package cj.geochat.ability.oauth.gateway;


import org.springframework.security.core.Authentication;

public interface AuthorizationService {

	Authentication findByToken(String token, Object details) throws Throwable;

}