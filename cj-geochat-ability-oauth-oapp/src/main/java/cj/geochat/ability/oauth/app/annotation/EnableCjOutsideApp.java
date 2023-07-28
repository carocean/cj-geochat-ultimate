package cj.geochat.ability.oauth.app.annotation;

import cj.geochat.ability.oauth.app.config.DefaultOutsideAppConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultOutsideAppConfiguration.class})
//@ConditionalOnWebApplication
public @interface EnableCjOutsideApp {
}
