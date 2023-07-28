package cj.geochat.ability.swagger.annotation;

import cj.geochat.ability.swagger.config.DefaultSwagger3Config;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
//@ComponentScan(basePackages = {"cj.geochat.ability.swagger"})
@Import({DefaultSwagger3Config.class})
//@Import({Swagger3Config.class, FixNpeForSpringfoxHandlerProviderBeanPostProcessorConfiguration.class})
//@ConditionalOnWebApplication
public @interface EnableCjSwagger {
}
