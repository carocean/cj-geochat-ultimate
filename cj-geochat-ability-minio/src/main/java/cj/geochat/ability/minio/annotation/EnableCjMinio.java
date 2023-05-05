package cj.geochat.ability.minio.annotation;

import cj.geochat.ability.minio.config.MinIoClientConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({MinIoClientConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjMinio {
}
