package cj.geochat.ability.mybatis.annotation;

import cj.geochat.ability.mybatis.config.AccessDBPolicy;
import cj.geochat.ability.mybatis.config.DefaultDataSourceConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultDataSourceConfig.class, AccessDBPolicy.class})
//@ConditionalOnWebApplication
public @interface EnableCjMybatisRW {
}
