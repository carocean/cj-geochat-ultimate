package cj.geochat.ability.minio.annotation;

import cj.geochat.ability.minio.config.DefaultMinIoClientConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultMinIoClientConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjMinio {
}
