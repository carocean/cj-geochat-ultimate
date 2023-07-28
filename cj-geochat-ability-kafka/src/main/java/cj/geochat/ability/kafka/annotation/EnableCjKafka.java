package cj.geochat.ability.kafka.annotation;

import cj.geochat.ability.kafka.config.DefaultKafkaConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultKafkaConfig.class})
public @interface EnableCjKafka {
}
