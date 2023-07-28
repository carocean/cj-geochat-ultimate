package cj.geochat.ability.elasticsearch.annotation;

import cj.geochat.ability.elasticsearch.config.DefaultElasticsearchConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultElasticsearchConfig.class})
//@ConditionalOnWebApplication
public @interface EnableCjElasticsearch {
}
