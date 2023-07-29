package cj.geochat.ability.oauth.gateway.annotation;

import cj.geochat.ability.oauth.gateway.config.DefaultAuthorizationGatewayConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultAuthorizationGatewayConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjGateway {
}
