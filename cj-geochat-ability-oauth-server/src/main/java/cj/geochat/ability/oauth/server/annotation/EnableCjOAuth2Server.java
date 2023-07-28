package cj.geochat.ability.oauth.server.annotation;

import cj.geochat.ability.oauth.server.config.DefaultAuthorizationServerConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultAuthorizationServerConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjOAuth2Server {
}
