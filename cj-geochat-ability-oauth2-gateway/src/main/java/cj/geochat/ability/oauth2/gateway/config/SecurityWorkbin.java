package cj.geochat.ability.oauth2.gateway.config;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth2.common.ResultCodeTranslator;
import cj.geochat.ability.oauth2.gateway.*;
import cj.geochat.ability.oauth2.gateway.properties.SecurityProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.oauth2.server.resource.web.server.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;

import javax.naming.AuthenticationException;
import java.io.IOException;

@EnableConfigurationProperties(SecurityProperties.class)
public abstract class SecurityWorkbin {
    @Autowired
    private ApplicationContext applicationContext;
    @Autowired
    protected SecurityProperties securityProperties;

    @Bean
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setOutputStreaming(false);
        restTemplate.setRequestFactory(requestFactory);
        restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public void handleError(ClientHttpResponse response) throws IOException {
                if (response.getRawStatusCode() != 401) {
                    super.handleError(response);
                }
            }
        });
        return restTemplate;
    }

    @Bean
    public TokenStore tokenStore() {
        RedisConnectionFactory redisConnectionFactory = applicationContext.getBean(RedisConnectionFactory.class);
        return new RedisTokenStore(redisConnectionFactory);
    }

    @Bean("customAuthManagerHandler")
    public ReactiveAuthorizationManager<AuthorizationContext> authManagerHandler() {
        ICheckPermission checkPermission=createCheckPermission();
        return new DefaultAuthManagerHandler(checkPermission);
    }
    protected ICheckPermission createCheckPermission(){
        return new DefaultCheckPermission();
    }
    @Bean("customAccessDeniedHandler")
    public DefaultAccessDeniedHandler accessDeniedHandler() {
        return new DefaultAccessDeniedHandler(securityProperties);
    }

    @Bean("customAuthenticationEntryPoint")
    public ServerAuthenticationEntryPoint authenticationEntryPoint() {
        return new DefaultUnauthorizedEntryPoint(securityProperties);
    }

    public WebFilter errorWebFilter() {
        return ((exchange, chain) -> {
            try {
                return chain.filter(exchange);
            } catch (Exception e) {
                ResultCode rc = null;
                if (e instanceof AuthenticationException) {
                    rc = ResultCodeTranslator.translateException((org.springframework.security.core.AuthenticationException) e);
                } else {
                    rc = ResultCode.ERROR_UNKNOWN;
                }
                Object r = R.of(rc, e.getMessage());
                ServerHttpResponse response = exchange.getResponse();
                try {
                    return response.writeAndFlushWith(Flux.just(ByteBufFlux.just(response.bufferFactory().wrap(new ObjectMapper().writeValueAsString(r).getBytes("UTF-8")))));
                } catch (Exception ex) {
                    return Mono.empty();
                }
            }
        });
    }

    public AuthenticationWebFilter authenticationWebFilter(TokenStore tokenStore, ITenantStore tenantStore) {
        //认证处理器
        ReactiveAuthenticationManager customAuthenticationManager = new CustomAuthenticationManager(tokenStore);
        JsonAuthenticationEntryPoint entryPoint = new JsonAuthenticationEntryPoint();
        //token转换器
        ServerBearerTokenAuthenticationConverter tokenAuthenticationConverter = new ServerBearerTokenAuthenticationConverter();
        tokenAuthenticationConverter.setAllowUriQueryParameter(true);
        //oauth2认证过滤器
        CustomAuthenticationWebFilter oauth2Filter = new CustomAuthenticationWebFilter(customAuthenticationManager);
        oauth2Filter.setServerAuthenticationConverter(tokenAuthenticationConverter);
        oauth2Filter.setServerAuthenticationFailureHandler(new Oauth2ExceptionHandler());
        oauth2Filter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(entryPoint));
        oauth2Filter.setAuthenticationSuccessHandler(new Oauth2AuthSuccessHandler(tenantStore));
        return oauth2Filter;
    }
}
