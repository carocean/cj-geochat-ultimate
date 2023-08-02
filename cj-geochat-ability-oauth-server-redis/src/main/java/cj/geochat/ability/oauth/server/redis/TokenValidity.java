package cj.geochat.ability.oauth.server.redis;

public interface TokenValidity {
    long getAccessTokenValidity(String registeredAppId);

    long getRefreshTokenValidity(String registeredAppId);

    long getAuthCodeTokenValidity(String registeredAppId);
}
