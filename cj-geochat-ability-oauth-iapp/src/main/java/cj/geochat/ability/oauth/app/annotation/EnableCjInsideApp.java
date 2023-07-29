package cj.geochat.ability.oauth.app.annotation;

import cj.geochat.ability.oauth.app.config.DefaultInsideAppConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * 网关之内的应用
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultInsideAppConfiguration.class})
//@ConditionalOnWebApplication
public @interface EnableCjInsideApp {
}
