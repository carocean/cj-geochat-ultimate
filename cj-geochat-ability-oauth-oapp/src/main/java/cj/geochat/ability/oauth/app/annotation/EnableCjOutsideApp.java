package cj.geochat.ability.oauth.app.annotation;

import cj.geochat.ability.oauth.app.config.DefaultOutsideAppConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

/**
 * 网关之外的应用
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultOutsideAppConfiguration.class})
//@ConditionalOnWebApplication
public @interface EnableCjOutsideApp {
}
