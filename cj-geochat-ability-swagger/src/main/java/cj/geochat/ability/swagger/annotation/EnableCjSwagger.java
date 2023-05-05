package cj.geochat.ability.swagger.annotation;

import org.springframework.context.annotation.ComponentScan;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@ComponentScan(basePackages = {"cj.geochat.ability.swagger"})
//@Import({Swagger3Config.class, FixNpeForSpringfoxHandlerProviderBeanPostProcessorConfiguration.class})
//@ConditionalOnWebApplication
public @interface EnableCjSwagger {
}
