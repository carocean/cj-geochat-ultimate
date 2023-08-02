package cj.geochat.ability.oauth.server.redis.dao;

import cj.geochat.ability.oauth.server.OAuth2Authorization;
import cj.geochat.ability.oauth.server.OAuth2AuthorizationCode;
import cj.geochat.ability.oauth.server.OAuth2ParameterNames;
import cj.geochat.ability.oauth.server.OAuth2TokenType;
import cj.geochat.ability.oauth.server.redis.OAuth2AuthorizationDAO;
import cj.geochat.ability.oauth.server.redis.TokenValidity;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.Assert;
import org.springframework.util.SerializationUtils;
import org.springframework.util.StringUtils;

import java.util.concurrent.TimeUnit;

public class DefaultAuthorizationDAO implements OAuth2AuthorizationDAO {
    private String keyPrefix = "oauth2:authorizations:completed";
    RedisTemplate<String, byte[]> redisTemplate;
    TokenValidity tokenValidity;

    public DefaultAuthorizationDAO(String keyPrefix, RedisTemplate<String, byte[]> redisTemplate, TokenValidity tokenValidity) {
        Assert.notNull(redisTemplate, "redisTemplate cannot be null");
        Assert.notNull(tokenValidity, "tokenValidity cannot be null");
        this.redisTemplate = redisTemplate;
        this.keyPrefix = keyPrefix;
        this.tokenValidity = tokenValidity;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        byte[] data = SerializationUtils.serialize(authorization);
        String idKey = getIdKey(authorization);
        long expire = getAccessTokenValidity(authorization);
        redisTemplate.opsForValue().set(idKey, data, expire * 1000, TimeUnit.MILLISECONDS);
        indexAuthorization(authorization.getId().getBytes(), authorization);
    }


    @Override
    public void remove(OAuth2Authorization authorization) {
        String idKey = getIdKey(authorization);
        redisTemplate.delete(idKey);
        indexDelete(authorization);
    }

    @Override
    public OAuth2Authorization findById(String id) {
        OAuth2Authorization authorization = null;
        String idKey = getIdKey(id);
        if (StringUtils.hasText(idKey)) {
            byte[] data = redisTemplate.opsForValue().get(idKey);
            if (data != null) {
                authorization = (OAuth2Authorization) SerializationUtils.deserialize(data);
            }
        }
        return authorization;
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            OAuth2Authorization authorization = null;
            authorization = findByState(token);
            if (authorization != null) {
                return authorization;
            }
            authorization = findByCode(token);
            if (authorization != null) {
                return authorization;
            }
            authorization = findByAccessToken(token);
            if (authorization != null) {
                return authorization;
            }
            authorization = findByRefreshToken(token);
            if (authorization != null) {
                return authorization;
            }
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            return findByState(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            return findByCode(token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            return findByAccessToken(token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            return findByRefreshToken(token);
        }
        return null;
    }

    private OAuth2Authorization findByRefreshToken(String token) {
        String key = String.format("%s:refresh_token:%s", keyPrefix, token);
        byte[] idData = redisTemplate.opsForValue().get(key);
        if (idData == null) {
            return null;
        }
        String id = new String(idData);
        if (!StringUtils.hasText(id)) {
            return null;
        }
        return findById(id);
    }

    private OAuth2Authorization findByAccessToken(String token) {
        String key = String.format("%s:access_token:%s", keyPrefix, token);
        byte[] idData = redisTemplate.opsForValue().get(key);
        if (idData == null) {
            return null;
        }
        String id = new String(idData);
        if (!StringUtils.hasText(id)) {
            return null;
        }
        return findById(id);
    }

    private OAuth2Authorization findByCode(String token) {
        String key = String.format("%s:code:%s", keyPrefix, token);
        byte[] idData = redisTemplate.opsForValue().get(key);
        if (idData == null) {
            return null;
        }
        String id = new String(idData);
        if (!StringUtils.hasText(id)) {
            return null;
        }
        return findById(id);
    }

    private OAuth2Authorization findByState(String token) {
        String key = String.format("%s:state:%s", keyPrefix, token);
        byte[] idData = redisTemplate.opsForValue().get(key);
        if (idData == null) {
            return null;
        }
        String idValue = new String(idData);
        if (!StringUtils.hasText(idValue)) {
            return null;
        }
        return findById(idValue);
    }

    private String getIdKey(OAuth2Authorization authorization) {
        return getIdKey(authorization.getId());
    }

    private String getIdKey(String id) {
        id = String.format("%s:id:%s", keyPrefix, id);
        return id;
    }


    //state,code,access_token,refresh_token,四个索引来索引参数id
    private void indexAuthorization(byte[] idValue, OAuth2Authorization authorization) {
        String access_token = authorization.getAccessToken() == null ? null : authorization.getAccessToken().getToken().getTokenValue();
        String refresh_token = authorization.getRefreshToken() == null ? null : authorization.getRefreshToken().getToken().getTokenValue();
        String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        String code = "";
        if (authorizationCode != null) {
            code = authorizationCode.getToken().getTokenValue();
        }
        if (StringUtils.hasText(access_token)) {
            String indexKey = String.format("%s:access_token:%s", keyPrefix, access_token);
            long expire = getAccessTokenValidity(authorization);
            redisTemplate.opsForValue().set(indexKey, idValue, expire * 1000, TimeUnit.MILLISECONDS);
        }
        if (StringUtils.hasText(refresh_token)) {
            String indexKey = String.format("%s:refresh_token:%s", keyPrefix, refresh_token);
            long expire = getRefreshTokenValidity(authorization);
            redisTemplate.opsForValue().set(indexKey, idValue, expire * 1000, TimeUnit.MILLISECONDS);
        }
        if (StringUtils.hasText(state)) {
            String indexKey = String.format("%s:state:%s", keyPrefix, state);
            long expire = getCodeTokenValidity(authorization);
            redisTemplate.opsForValue().set(indexKey, idValue, expire * 1000, TimeUnit.MILLISECONDS);
        }
        if (StringUtils.hasText(code)) {
            String indexKey = String.format("%s:code:%s", keyPrefix, code);
            long expire = getCodeTokenValidity(authorization);
            redisTemplate.opsForValue().set(indexKey, idValue, expire * 1000, TimeUnit.MILLISECONDS);
        }
    }

    private void indexDelete(OAuth2Authorization authorization) {
        String access_token = authorization.getAccessToken().getToken().getTokenValue();
        String refresh_token = authorization.getRefreshToken().getToken().getTokenValue();
        String state = authorization.getAttribute(OAuth2ParameterNames.STATE);
        OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
                authorization.getToken(OAuth2AuthorizationCode.class);
        String code = "";
        if (authorizationCode != null) {
            code = authorizationCode.getToken().getTokenValue();
        }
        if (StringUtils.hasText(access_token)) {
            String indexKey = String.format("%s:access_token:%s", keyPrefix, access_token);
            redisTemplate.delete(indexKey);
        }
        if (StringUtils.hasText(refresh_token)) {
            String indexKey = String.format("%s:refresh_token:%s", keyPrefix, refresh_token);
            redisTemplate.delete(indexKey);
        }
        if (StringUtils.hasText(state)) {
            String indexKey = String.format("%s:state:%s", keyPrefix, state);
            redisTemplate.delete(indexKey);
        }
        if (StringUtils.hasText(code)) {
            String indexKey = String.format("%s:code:%s", keyPrefix, code);
            redisTemplate.delete(indexKey);
        }
    }

    private long getAccessTokenValidity(OAuth2Authorization authorization) {
        long expire = 0;
        if (authorization.getAccessToken() != null) {
            expire = tokenValidity.getAccessTokenValidity(authorization.getRegisteredAppId());
        } else {
            expire = tokenValidity.getAuthCodeTokenValidity(authorization.getRegisteredAppId());
        }
        return expire;
    }

    private long getRefreshTokenValidity(OAuth2Authorization authorization) {
        long expire = 0;
        if (authorization.getRefreshToken() != null) {
            expire = tokenValidity.getRefreshTokenValidity(authorization.getRegisteredAppId());
        } else {
            expire = tokenValidity.getAuthCodeTokenValidity(authorization.getRegisteredAppId());
        }
        return expire;
    }

    private long getCodeTokenValidity(OAuth2Authorization authorization) {
        long expire = 0;
        expire = tokenValidity.getAuthCodeTokenValidity(authorization.getRegisteredAppId());
        return expire;
    }
}
