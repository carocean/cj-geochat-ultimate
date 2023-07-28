package cj.geochat.ability.redis.annotation;

import cj.geochat.ability.redis.config.DefaultRedisConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultRedisConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjRedis {
}
