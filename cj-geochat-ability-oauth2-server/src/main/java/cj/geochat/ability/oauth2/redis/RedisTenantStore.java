package cj.geochat.ability.oauth2.redis;

import cj.geochat.ability.redis.config.RedisConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.concurrent.TimeUnit;

@Component
@ConditionalOnBean({RedisConfig.class})
@Slf4j
public class RedisTenantStore implements ITenantStore {
    @Autowired
    private StringRedisTemplate redisTemplate;
    private static final String TENANT_KEY = "tenant_on_user_client:%s:%s";

    @Override
    public void storeTenant(String user,String client_id, String tenant_id) {
        String key = String.format(TENANT_KEY, user,client_id);
        log.debug("保存tenant：" + tenant_id);
        //保存30分钟
        redisTemplate.opsForValue().set(key, tenant_id, 30, TimeUnit.MINUTES);
    }

    @Override
    public void remoteTenant(String user, String client_id) {
        String key = String.format(TENANT_KEY, user,client_id);
        log.debug(String.format("移除用户:%s在client:%s上的tenant：" ,user,client_id));
        redisTemplate.delete(key);
    }
}
