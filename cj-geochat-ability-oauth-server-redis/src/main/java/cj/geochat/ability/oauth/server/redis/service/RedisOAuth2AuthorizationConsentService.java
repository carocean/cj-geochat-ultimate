package cj.geochat.ability.oauth.server.redis.service;

import cj.geochat.ability.oauth.server.OAuth2AuthorizationConsent;
import cj.geochat.ability.oauth.server.redis.TokenValidity;
import cj.geochat.ability.oauth.server.service.OAuth2AuthorizationConsentService;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.Assert;
import org.springframework.util.SerializationUtils;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

@Service
public class RedisOAuth2AuthorizationConsentService implements OAuth2AuthorizationConsentService, InitializingBean {
    @Autowired
    @Qualifier("bytesRedisTemplate")
    RedisTemplate<String, byte[]> redisTemplate;
    @Autowired
    ApplicationContext applicationContext;
    TokenValidity tokenValidity;
    @Override
    public void afterPropertiesSet() throws Exception {
         tokenValidity = applicationContext.getBean(TokenValidity.class);
        Assert.notNull(tokenValidity, "tokenValidity cannot be null");
    }

    @Override
    public void save(OAuth2AuthorizationConsent authorizationConsent) {
        String id = getId(authorizationConsent);
        byte[] data = SerializationUtils.serialize(authorizationConsent);
        long codeValidity = tokenValidity.getAuthCodeTokenValidity(authorizationConsent.getRegisteredAppId());
        redisTemplate.opsForValue().set(id, data,codeValidity*1000, TimeUnit.MILLISECONDS );
    }

    @Override
    public void remove(OAuth2AuthorizationConsent authorizationConsent) {
        String id = getId(authorizationConsent);
        redisTemplate.delete(id);
    }

    @Override
    public OAuth2AuthorizationConsent findById(String registeredAppId, String principalName) {
        Assert.hasText(registeredAppId, "registeredAppId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        String id = getId(registeredAppId, principalName);
        byte[] data = redisTemplate.opsForValue().get(id);
        OAuth2AuthorizationConsent consent = (OAuth2AuthorizationConsent) SerializationUtils.deserialize(data);
        return consent;
    }


    private static String getId(String registeredAppId, String principalName) {
        String id = Objects.hash(registeredAppId, principalName) + "";
        id = String.format("oauth2:consent:%s", id);
        return id;
    }

    private static String getId(OAuth2AuthorizationConsent authorizationConsent) {
        return getId(authorizationConsent.getRegisteredAppId(), authorizationConsent.getPrincipalName());
    }
}
