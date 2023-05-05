package cj.geochat.ability.api.annotation;

import cj.geochat.ability.api.config.ApiWebAppConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({ApiWebAppConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjApi {
}
