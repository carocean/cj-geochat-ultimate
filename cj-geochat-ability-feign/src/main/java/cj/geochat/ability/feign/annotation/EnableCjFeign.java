package cj.geochat.ability.feign.annotation;

import cj.geochat.ability.feign.config.DefaultFeignConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultFeignConfiguration.class})
//@ConditionalOnWebApplication
public @interface EnableCjFeign {
}
