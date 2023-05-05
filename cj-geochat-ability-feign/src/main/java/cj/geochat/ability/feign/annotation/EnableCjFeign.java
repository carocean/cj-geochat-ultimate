package cj.geochat.ability.feign.annotation;

import cj.geochat.ability.feign.config.FeignConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({FeignConfiguration.class})
//@ConditionalOnWebApplication
public @interface EnableCjFeign {
}
