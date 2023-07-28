package cj.geochat.ability.eureka.annotation;

import cj.geochat.ability.eureka.config.DefaultEurekaConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultEurekaConfig.class})
public @interface EnableCjEureka {
}
