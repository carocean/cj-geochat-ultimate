package cj.geochat.ability.feign.config;

import cj.geochat.ability.feign.ResultDecoder;
import feign.Contract;
import feign.MethodMetadata;
import feign.Types;
import feign.Util;
import feign.codec.Decoder;
import feign.optionals.OptionalDecoder;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.http.HttpMessageConverters;
import org.springframework.cloud.openfeign.support.HttpMessageConverterCustomizer;
import org.springframework.cloud.openfeign.support.ResponseEntityDecoder;
import org.springframework.cloud.openfeign.support.SpringDecoder;
import org.springframework.cloud.openfeign.support.SpringMvcContract;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Configuration(proxyBeanMethods = false)
public class FeignConfiguration {

    @Autowired
    private ObjectFactory<HttpMessageConverters> messageConverters;

    @Bean
    public Decoder feignDecoder(ObjectProvider<HttpMessageConverterCustomizer> customizers) {
        return new OptionalDecoder(new ResponseEntityDecoder(new ResultDecoder(new SpringDecoder(this.messageConverters, customizers))));
    }

    @Bean
    @ConditionalOnMissingBean
    public Contract feignContract() {
        return new GeochatSpringMvcContract();
    }

    public class GeochatSpringMvcContract extends SpringMvcContract {
        @Override
        public List<MethodMetadata> parseAndValidateMetadata(Class<?> targetType) {
            Util.checkState(targetType.getTypeParameters().length == 0, "Parameterized types unsupported: %s", new Object[]{targetType.getSimpleName()});
            //充许feign继承多个接口，但父接口最好不要包含RequestMapping注解
            //            Util.checkState(targetType.getInterfaces().length <= 1, "Only single inheritance supported: %s", new Object[]{targetType.getSimpleName()});
            Map<String, MethodMetadata> result = new LinkedHashMap();
            Method[] methods = targetType.getMethods();
            int length = methods.length;

            for (int i = 0; i < length; ++i) {
                Method method = methods[i];
                RequestMapping requestMapping = method.getAnnotation(RequestMapping.class);
                if (requestMapping == null) {
                    continue;
                }
                if (method.getDeclaringClass() != Object.class && (method.getModifiers() & 8) == 0 && !Util.isDefault(method)) {
                    MethodMetadata metadata = this.parseAndValidateMetadata(targetType, method);
                    if (result.containsKey(metadata.configKey())) {
                        MethodMetadata existingMetadata = (MethodMetadata) result.get(metadata.configKey());
                        Type existingReturnType = existingMetadata.returnType();
                        Type overridingReturnType = metadata.returnType();
                        Type resolvedType = Types.resolveReturnType(existingReturnType, overridingReturnType);
                        if (resolvedType.equals(overridingReturnType)) {
                            result.put(metadata.configKey(), metadata);
                        }
                    } else {
                        result.put(metadata.configKey(), metadata);
                    }
                }
            }

            return new ArrayList(result.values());
        }
    }
}

