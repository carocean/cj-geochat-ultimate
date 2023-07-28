package cj.geochat.ability.websocket.annotation;

import cj.geochat.ability.websocket.config.DefaultWebSocketConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultWebSocketConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjWebsocket {
}
