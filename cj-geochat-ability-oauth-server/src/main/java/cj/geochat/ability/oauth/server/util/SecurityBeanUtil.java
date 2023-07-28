package cj.geochat.ability.oauth.server.util;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import java.lang.reflect.Field;

@Slf4j
public class SecurityBeanUtil {
    public static ApplicationContext getContext(HttpSecurity http) {
        return http.getSharedObject(ApplicationContext.class);
    }

    public static <T> T getBean(HttpSecurity http, Class<T> clazz) {
        T result = http.getSharedObject(clazz);
        if (result != null) {
            return result;
        }
        var context = getContext(http);
        result = context.getBean(clazz);
        return result;
    }

    public static <T> T getBean(HttpSecurity http, Class<T> clazz, T defaultValue) {
        T result = http.getSharedObject(clazz);
        if (result != null) {
            return result;
        }
        var context = getContext(http);
        try {
            result = context.getBean(clazz);
        } catch (BeansException e) {
            log.info(e.getMessage());
        }
        if (result == null) {
            result = defaultValue;
            http.setSharedObject(clazz, defaultValue);
        }
        return result;
    }

    public static Object getBean(HttpSecurity http, String beanName, Object defaultValue) {
        Object result = http.getSharedObjects().get(beanName);
        if (result != null) {
            return result;
        }
        var context = getContext(http);
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
