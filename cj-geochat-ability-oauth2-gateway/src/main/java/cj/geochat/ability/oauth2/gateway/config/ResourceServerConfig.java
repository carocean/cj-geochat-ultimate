package cj.geochat.ability.oauth2.gateway.config;

import cj.geochat.ability.oauth2.gateway.ITenantStore;
import cj.geochat.ability.oauth2.gateway.properties.SecurityProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.web.server.WebFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
@ComponentScan("cj.geochat.ability.oauth2.gateway")
@EnableConfigurationProperties(SecurityProperties.class)
@ConditionalOnBean({SecurityWorkbin.class})
public class ResourceServerConfig {

    @Autowired(required = false)
    SecurityWorkbin securityWorkbin;
    @Autowired
    SecurityProperties securityProperties;
    @Autowired(required = false)
    TokenStore tokenStore;
    @Autowired
    ITenantStore tenantStore;

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        //这个filter必须放到前面设置
        http.addFilterBefore(securityWorkbin.errorWebFilter(), SecurityWebFiltersOrder.FIRST);
        http.addFilterAt(securityWorkbin.authenticationWebFilter(tokenStore, tenantStore), SecurityWebFiltersOrder.AUTHENTICATION);
        List<String> whitelist = securityProperties.getWhitelist();
        List<String> staticResources = securityProperties.getStaticlist();
        List<String> allWhitelist = new ArrayList<>();
        allWhitelist.addAll(whitelist);
        allWhitelist.addAll(staticResources);
        http.cors().and().csrf().disable()
                //拒绝匿名用户
                .anonymous().disable()
                //注释掉。建议使用认证中心或认证服务中心退出，网关只是访问和控制资源。
//                .logout().logoutUrl("/logout").logoutSuccessHandler(securityWorkbin.serverLogoutSuccessHandler())//logout默认以post提交,可以参考修改：.requiresLogout(new PathRequestMatcher("/logout", "GET"))
                .headers().frameOptions().disable()
                .and()
                .exceptionHandling()
                .accessDeniedHandler(securityWorkbin.accessDeniedHandler())
                .authenticationEntryPoint(securityWorkbin.authenticationEntryPoint())
                .and().authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll() //o
                .pathMatchers(allWhitelist.toArray(new String[0])).permitAll()  //无需进行权限过滤的请求路径:"/token", "/token/**", "/refresh_token", "/oauth2/**", "/logout"
                .pathMatchers("/**").access(securityWorkbin.authManagerHandler())//访问权限拦截和实现处
                .anyExchange().authenticated()
        ;
        return http.build();
    }


}

