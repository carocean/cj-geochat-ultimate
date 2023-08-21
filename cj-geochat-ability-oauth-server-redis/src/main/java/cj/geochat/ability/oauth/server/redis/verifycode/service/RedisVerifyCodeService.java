package cj.geochat.ability.oauth.server.redis.verifycode.service;

import cj.geochat.ability.oauth.server.entrypoint.verifycode.IVerifyCodeService;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.util.SerializationUtils;

import java.util.concurrent.TimeUnit;

@Service
public class RedisVerifyCodeService implements IVerifyCodeService {
    private String keyPrefix = "oauth2:verifycode";
    @Autowired
    @Qualifier("bytesRedisTemplate")
    RedisTemplate<String, byte[]> redisTemplate;

    @Override
    public void save(VerifyCodeInfo verifyCodeInfo) {
        byte[] data = SerializationUtils.serialize(verifyCodeInfo);
        String key = getIdKey(verifyCodeInfo.getPrincipal());
        redisTemplate.opsForValue().set(key, data, 5, TimeUnit.MINUTES);
    }

    @Override
    public VerifyCodeInfo read(String principal) {
        String key = getIdKey(principal);
        byte[] b = redisTemplate.opsForValue().get(key);
        if (b == null || b.length == 0) {
            return null;
        }
        VerifyCodeInfo verifyCodeInfo = (VerifyCodeInfo) SerializationUtils.deserialize(b);
        return verifyCodeInfo;
    }

    private String getIdKey(String id) {
        id = String.format("%s:id:%s", keyPrefix, id);
        return id;
    }
}
