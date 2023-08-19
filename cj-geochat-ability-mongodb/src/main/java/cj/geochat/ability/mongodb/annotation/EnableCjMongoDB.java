package cj.geochat.ability.mongodb.annotation;

import cj.geochat.ability.mongodb.config.DefaultCloseAutoMongoConfig;
import org.springframework.boot.autoconfigure.data.mongo.MongoDataAutoConfiguration;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultCloseAutoMongoConfig.class,MongoAutoConfiguration.class, MongoDataAutoConfiguration.class})
public @interface EnableCjMongoDB {
}
