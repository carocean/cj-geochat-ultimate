package cj.geochat.ability.swagger.config;


import cj.geochat.ability.swagger.SwaggerProperties;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.regex.Pattern;

/**
 * 使用knife4j替代swagger-ui
 */
@Configuration
@EnableConfigurationProperties(SwaggerProperties.class)
@Slf4j
public class DefaultSwagger3Config implements InitializingBean {
    @Autowired
    private SwaggerProperties swaggerProperties;
    @Autowired
    private ApplicationContext applicationContext;
    private Pattern apiVersionPattern;

    @Override
    public void afterPropertiesSet() throws Exception {
        if (!swaggerProperties.isEnabled()) {
            return;
        }
    }

    /**
     * SpringDoc 标题、描述、版本等信息配置
     *
     * @return openApi 配置信息
     */
    @Bean
    public OpenAPI springDocOpenAPI() {
        return new OpenAPI().info(new Info()
                        .title("YiYi API")
                        .description("YiYi接口文档说明")
                        .version("v0.0.1-SNAPSHOT")
                        .license(new License().name("YiYi项目博客专栏")
                                .url("https://blog.csdn.net/weihao0240/category_12166012.html")))
//                .externalDocs(new ExternalDocumentation()
//                        .description("码云项目地址")
//                        .url("https://gitee.com/jack0240/YiYi"))
                // 配置Authorizations
                .components(new Components().addSecuritySchemes("bearer-key",
                        new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer")));
    }

    /**
     * demo 分组
     *
     * @return demo分组接口
     */
    @Bean
    public GroupedOpenApi siteApi() {
        return GroupedOpenApi.builder()
                .group("demo接口")
                .pathsToMatch("/demo/**")
                .build();
    }

    /**
     * sys 分组
     *
     * @return sys分组接口
     */
    @Bean
    public GroupedOpenApi adminApi() {
        return GroupedOpenApi.builder()
                .group("sys接口")
                .pathsToMatch("/sys/**")
                .build();
    }
}