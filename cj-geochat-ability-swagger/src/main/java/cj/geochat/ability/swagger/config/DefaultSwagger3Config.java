package cj.geochat.ability.swagger.config;


import cj.geochat.ability.swagger.SwaggerProperties;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.ExternalDocumentation;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.media.StringSchema;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;
import org.springdoc.core.models.GroupedOpenApi;
import org.springdoc.core.properties.SpringDocConfigProperties;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;

/**
 * 使用knife4j替代swagger-ui
 */
@Configuration
@EnableConfigurationProperties(SwaggerProperties.class)
@Slf4j
public class DefaultSwagger3Config implements BeanPostProcessor {
    @Autowired
    private SwaggerProperties properties;
    @Autowired
    ApplicationContext context;

    @Bean
    public OpenAPI springDocOpenAPI() {
        Info info = properties.getInfo();
        License license = info.getLicense() == null ? new License() : info.getLicense();
        Contact contact = info.getContact() == null ? new Contact() : info.getContact();
        SecurityScheme token = properties.getToken();
        ExternalDocumentation externalDocumentation = properties.getExternalDocs();

        OpenAPI openAPI = new OpenAPI().info(new Info()
                .title(info.getTitle())
                .description(info.getDescription())
                .version(info.getVersion())
                .summary(info.getSummary())
                .contact(new Contact()
                        .name(contact.getName())
                        .url(contact.getUrl())
                        .email(contact.getEmail())
                )
                .license(new License()
                        .name(license.getName())
                        .url(license.getUrl())
                        .identifier(license.getIdentifier())
                )
        );
        if (externalDocumentation != null) {
            openAPI.externalDocs(externalDocumentation);
        }
        if (token != null) {
            openAPI.components(new Components()
                            .addSecuritySchemes(token.getName(), token)
                            .addParameters(token.getName(), new Parameter()
                                    .name(token.getName())
                                    .in(token.getIn().name())
                                    .schema(new StringSchema().name(token.getScheme()))
                            )
                    )
                    .addSecurityItem(new SecurityRequirement()
                            .addList(token.getName())
                    )
            ;
        }
        // 配置Authorizations
        return openAPI;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        //为配置的组添加参数。这是因为：
        // 添加自定义配置，这里添加了一个用户认证的 header，否则 knife4j 里会没有 header
//        AntPathMatcher antPathMatcher = new AntPathMatcher();
        if (SpringDocConfigProperties.class.isAssignableFrom(bean.getClass()) && properties.getToken() != null) {
            SpringDocConfigProperties springDocConfigProperties = (SpringDocConfigProperties) bean;
            springDocConfigProperties.getGroupConfigs().forEach(groupConfig -> {
                GroupedOpenApi groupedOpenApi = (GroupedOpenApi) context.getBean(groupConfig.getGroup());
//注掉原因：如果组的路径集合中包含有开放api，而集合中还含有非开放api，则要么全无安全参数，要么全有，这很奇怪，因此干脆全有吧。
                //                var pathToMatches = groupedOpenApi.getPathsToMatch();
//                //系统设为固定开放的api，这些api是不需要在swagger-ui中要求安全参数的.
//                boolean containsPublicPath = false;
//                for (var item : pathToMatches) {
//                    if (groupedOpenApi.getGroup().endsWith("-public-api") && StringUtils.hasText(item) && antPathMatcher.match("/public/v{id:[0-9]+}/**", item)) {
//                        containsPublicPath = true;
//                        break;
//                    }
//                }
//                if (containsPublicPath) {
//                    return;
//                }
                groupedOpenApi.addAllOperationCustomizer(
                        Collections.singletonList(
                                (operation, handlerMethod) -> operation.security(
                                        Collections.singletonList(
                                                new SecurityRequirement()
                                                        .addList(properties
                                                                .getToken()
                                                                .getName()
                                                        )
                                        ))
                        )
                );
            });

        }
        return BeanPostProcessor.super.postProcessBeforeInitialization(bean, beanName);
    }

}