//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package cj.geochat.ability.oauth2.gateway.annotation;

import cj.geochat.ability.oauth2.gateway.config.DefaultSecurityConfig;
import cj.geochat.ability.oauth2.gateway.config.WebClientConfig;
import org.springframework.context.annotation.Import;

import java.lang.annotation.*;

@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE})
@Documented
@Import({DefaultSecurityConfig.class, WebClientConfig.class})
public @interface EnableCjOAuth2Gateway {
}