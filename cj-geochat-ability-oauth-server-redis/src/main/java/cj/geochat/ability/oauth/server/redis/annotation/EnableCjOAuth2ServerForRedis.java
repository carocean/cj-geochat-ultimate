package cj.geochat.ability.oauth.server.redis.annotation;

import cj.geochat.ability.oauth.server.redis.config.DefaultOAuth2ServerRedisConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultOAuth2ServerRedisConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjOAuth2ServerForRedis {
}
