package cj.geochat.ability.oauth.gateway.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import java.lang.reflect.Field;

@Slf4j
public class ServerHttpSecurityUtil {
    public static ApplicationContext getContext(ServerHttpSecurity http) {
        try {
            Field field = ServerHttpSecurity.class.getDeclaredField("context");
            field.setAccessible(true);
            return (ApplicationContext) field.get(http);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> T getBean(ServerHttpSecurity http, Class<T> clazz, T defaultValue) {
        var context = ServerHttpSecurityUtil.getContext(http);
        T result = null;
        try {
            result = context.getBean(clazz);
        } catch (BeansException e) {
            log.info(e.getMessage());
        }
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    public static Object getBean(ServerHttpSecurity http, String beanName, Object defaultValue) {
        var context = ServerHttpSecurityUtil.getContext(http);
        Object result = null;
        try {
            result = context.getBean(beanName);
        } catch (BeansException e) {
            log.info(e.getMessage());
        }
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }
}
