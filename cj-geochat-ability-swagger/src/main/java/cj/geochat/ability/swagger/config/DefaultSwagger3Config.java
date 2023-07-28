package cj.geochat.ability.swagger.config;

import cj.geochat.ability.swagger.SwaggerGlobalParameter;
import cj.geochat.ability.swagger.SwaggerProperties;
import cj.geochat.ability.swagger.SwaggerResponseMsg;
import com.github.xiaoymin.knife4j.spring.annotations.EnableKnife4j;
import io.swagger.annotations.Api;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import springfox.documentation.builders.*;
import springfox.documentation.oas.annotations.EnableOpenApi;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 使用knife4j替代swagger-ui
 */
@Configuration
@EnableOpenApi
@EnableKnife4j
@EnableConfigurationProperties(SwaggerProperties.class)
@Slf4j
public class DefaultSwagger3Config implements InitializingBean {
    @Autowired
    private SwaggerProperties swaggerProperties;
    @Autowired
    private ApplicationContext applicationContext;
    private Pattern apiVersionPattern;

    @Bean
    @ConditionalOnMissingBean(Docket.class)
    //默认分组，即所有接口
    public Docket defaultDocket() {
        log.info(String.format("Swagger3状态：%s", swaggerProperties.isEnabled()));
        String groupName = StringUtils.hasText(swaggerProperties.getDefaultGroupName()) ? swaggerProperties.getDefaultGroupName() : "所有接口";
        return new Docket(DocumentationType.OAS_30)
                //由于组在ui中的排名按首字姆排序，所以默认组前缀固定为All排第1
                .groupName(String.format("All-%s", groupName))
                //加载配置信息
                .apiInfo(apiInfo())
                .enable(swaggerProperties.isEnabled())
                //设置全局参数
                .globalRequestParameters(globalParamBuilder())
                //设置全局响应参数
                .globalResponses(HttpMethod.GET, responseBuilder())
                .globalResponses(HttpMethod.POST, responseBuilder())
                .globalResponses(HttpMethod.PUT, responseBuilder())
                .globalResponses(HttpMethod.DELETE, responseBuilder())
                .select()
                .apis(RequestHandlerSelectors.withClassAnnotation(Api.class))
                .apis(RequestHandlerSelectors.basePackage(swaggerProperties.getBasePackage()))
                .paths(PathSelectors.any())
                .build()
                //设置安全认证
                .securityContexts(securityContexts())
                .securitySchemes(securitySchemes());

    }

    private Docket buildDocket(String groupName, int version) {
        return new Docket(DocumentationType.OAS_30)
                .apiInfo(apiInfo())
                .groupName(groupName)
                .enable(swaggerProperties.isEnabled())
                //设置全局参数
                .globalRequestParameters(globalParamBuilder())
                //设置全局响应参数
                .globalResponses(HttpMethod.GET, responseBuilder())
                .globalResponses(HttpMethod.POST, responseBuilder())
                .globalResponses(HttpMethod.PUT, responseBuilder())
                .globalResponses(HttpMethod.DELETE, responseBuilder())
                .select()
                .apis(method -> {
                    // 方法所在的类是否标注了?
                    RequestMapping apiMapping = method.getHandlerMethod().getBeanType().getAnnotation(RequestMapping.class);
                    if (apiMapping != null) {
                        return matchApiMapping(version, apiMapping.value(), apiMapping.path());
                    }
                    // 每个方法会进入这里进行判断并归类到不同分组，**请不要调换下面两段代码的顺序，在方法上的注解有优先级**
                    // 该方法上标注了版本
                    if (method.isAnnotatedWith(RequestMapping.class)) {
                        apiMapping = method.getHandlerMethod().getMethodAnnotation(RequestMapping.class);
                        return matchApiMapping(version, apiMapping.value(), apiMapping.path());
                    }

                    return false;
                })
                .paths(PathSelectors.any())
                .build() //设置安全认证
                .securityContexts(securityContexts())
                .securitySchemes(securitySchemes());
    }

    private boolean matchApiMapping(int version, String[] mValue, String[] mPath) {
        String urlMapping = mValue.length < 1 ? "" : mValue[0];
        if (!StringUtils.hasText(urlMapping)) {
            urlMapping = mPath.length < 1 ? "" : mPath[0];
        }
        Matcher matcher = apiVersionPattern.matcher(urlMapping);
        if (!matcher.find() || matcher.groupCount() < 1) {
            return false;
        }
        String v = matcher.group(1);
        if (Integer.valueOf(v) == version) {
            return true;
        }
        return false;
    }


    /**
     * 动态得创建Docket bean
     *
     * @throws Exception
     */
    @Override
    public void afterPropertiesSet() throws Exception {
        if (!swaggerProperties.isEnabled()) {
            return;
        }
//        doDefaultDocket();//不用动态创建默认组，没必要。
        doBuildDocket();
    }

    private void setApiVersionPattern() {
        String apiVersionPattern = swaggerProperties.getApiVersionPattern();
        apiVersionPattern = StringUtils.hasText(apiVersionPattern) ? apiVersionPattern : "^/api/v(\\d+)";
        this.apiVersionPattern = Pattern.compile(apiVersionPattern, Pattern.DOTALL);
    }

    /*
    //如果开启，则需要将defaultDocker()方法改为private，方法注解去掉
        private void doDefaultDocket() {
            // 动态注入bean
            AutowireCapableBeanFactory autowireCapableBeanFactory = applicationContext.getAutowireCapableBeanFactory();
            if (autowireCapableBeanFactory instanceof DefaultListableBeanFactory) {
                DefaultListableBeanFactory capableBeanFactory = (DefaultListableBeanFactory) autowireCapableBeanFactory;
                AbstractBeanDefinition beanDefinition = BeanDefinitionBuilder
                        .genericBeanDefinition()
                        .setFactoryMethodOnBean("defaultDocket", "swagger2Config")
                        .getBeanDefinition();
                capableBeanFactory.registerBeanDefinition("#swaggerDefault", beanDefinition);

            }
        }
     */
    private void doBuildDocket() {
        setApiVersionPattern();
        // 动态注入bean
        AutowireCapableBeanFactory autowireCapableBeanFactory = applicationContext.getAutowireCapableBeanFactory();
        if (autowireCapableBeanFactory instanceof DefaultListableBeanFactory) {
            DefaultListableBeanFactory capableBeanFactory = (DefaultListableBeanFactory) autowireCapableBeanFactory;
            int maxVersion = swaggerProperties.getMaxVersion();
            for (int i = 0; i < maxVersion; i++) {
                // 要注意 "工厂名和方法名"，意思是用这个bean的指定方法创建docket
                int currVersion = i + 1;
                AbstractBeanDefinition beanDefinition = BeanDefinitionBuilder
                        .genericBeanDefinition()
                        .setFactoryMethodOnBean("buildDocket", "swagger3Config")
                        .addConstructorArgValue(String.format("版本_%s", currVersion))
                        .addConstructorArgValue(currVersion)
                        .getBeanDefinition();
                capableBeanFactory.registerBeanDefinition(String.format("#swaggerVersion%s", currVersion), beanDefinition);
            }
        }
    }


    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title(swaggerProperties.getApiInfo().getTitle())
                .description(swaggerProperties.getApiInfo().getDescription())
                .contact(new Contact(swaggerProperties.getApiInfo().getContact(), swaggerProperties.getApiInfo().getUrl(), swaggerProperties.getApiInfo().getEmail()))
                .version(swaggerProperties.getApiInfo().getVersion())
                .build();
    }

    private List<SecurityContext> securityContexts() {
        return Arrays.asList(SecurityContext.builder()
                .securityReferences(defaultAuth())
                .forPaths(PathSelectors.any())
                .build());
    }

    /**
     * 安全认证参数
     *
     * @return
     */
    private List<SecurityScheme> securitySchemes() {
        SwaggerGlobalParameter parameter = swaggerProperties.getTokenParameter();
        List<SecurityScheme> list = new ArrayList<>();
        if (parameter == null) {
            return list;
        }
        list.add(
                new ApiKey(parameter.getName(), parameter.getName(), parameter.getTokenIn())
        );
        return list;
    }

    private List<SecurityReference> defaultAuth() {
        SwaggerGlobalParameter parameter = swaggerProperties.getTokenParameter();
        if (parameter == null) {
            return new ArrayList<>();
        }
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[]{
                new AuthorizationScope("all", "all scope")
        };
        return Arrays.asList(
                new SecurityReference(parameter.getName(), authorizationScopes)
        );
    }

    /**
     * 构建全局参数列表
     *
     * @return
     */
    private List<RequestParameter> globalParamBuilder() {
        List<RequestParameter> pars = new ArrayList<>();
        SwaggerGlobalParameter tokenParameter = swaggerProperties.getTokenParameter();
        if (tokenParameter != null) {
            pars.add(parameterBuilder(
                    tokenParameter.getName(),
                    tokenParameter.getDesc(),
                    tokenParameter.getTokenIn(),
                    tokenParameter.isRequired())
                    .build());
        }
        List<SwaggerGlobalParameter> parameters = swaggerProperties.getParameters();
        for (SwaggerGlobalParameter parameter : parameters) {
            pars.add(parameterBuilder(
                    parameter.getName(),
                    parameter.getDesc(),
                    parameter.getTokenIn(),
                    parameter.isRequired())
                    .build());
        }
        return pars;
    }

    /**
     * 创建参数
     *
     * @return
     */
    private RequestParameterBuilder parameterBuilder(String name, String desc, String parameterType, boolean required) {
        RequestParameterBuilder tokenPar = new RequestParameterBuilder();
        tokenPar
                .name(name)
                .description(desc)
                .in(parameterType)
                .required(required)
                .build();
        return tokenPar;
    }

    /**
     * 创建全局响应值
     *
     * @return
     */
    private List<Response> responseBuilder() {
        List<SwaggerResponseMsg> msgList = swaggerProperties.getResponseMsg();
        if (msgList == null) {
            return Arrays.asList();
        }
        List<Response> responseMessageList = new ArrayList<>();
        for (SwaggerResponseMsg msg : msgList) {
            responseMessageList.add(new ResponseBuilder()
                    .code(msg.getCode() + "")
                    .description(msg.getMessage())
                    .build());
        }
        return responseMessageList;
    }
}