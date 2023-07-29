package cj.geochat.ability.oauth.gateway.oauth2;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.gateway.*;
import cj.geochat.ability.oauth.gateway.filter.DefaultAuthenticationWebFilter;
import cj.geochat.ability.oauth.gateway.properties.DefaultSecurityProperties;
import cj.geochat.ability.oauth.gateway.service.RestAuthorizationService;
import cj.geochat.ability.oauth.gateway.util.ServerHttpSecurityUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;

import javax.naming.AuthenticationException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class OAuth2AuthorizationGatewayConfigurer {
    AuthorizationService authorizationService;
    ServerAuthenticationEntryPoint failureEntryPoint;
    ServerAuthenticationSuccessHandler successHandler;
    ServerAuthenticationConverter converter;
    ReactiveAuthenticationManager authenticationManager;
    ReactiveAuthorizationManager authorizationManager;
    ServerAccessDeniedHandler accessDeniedHandler;
    ServerAuthenticationEntryPoint unauthorizedEntryPoint;
    ICheckPermission checkPermission;
    RestTemplate restTemplate;
    DefaultSecurityProperties properties;

    public void setAuthorizationService(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    public void setCheckPermission(ICheckPermission checkPermission) {
        this.checkPermission = checkPermission;
    }

    public void setFailureEntryPoint(ServerAuthenticationEntryPoint failureEntryPoint) {
        this.failureEntryPoint = failureEntryPoint;
    }

    public void setSuccessHandler(ServerAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    public void setConverter(ServerAuthenticationConverter converter) {
        this.converter = converter;
    }

    public void setAuthenticationManager(ReactiveAuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    public void setAuthorizationManager(ReactiveAuthorizationManager authorizationManager) {
        this.authorizationManager = authorizationManager;
    }

    public void setAccessDeniedHandler(ServerAccessDeniedHandler accessDeniedHandler) {
        this.accessDeniedHandler = accessDeniedHandler;
    }

    public void setUnauthorizedEntryPoint(ServerAuthenticationEntryPoint unauthorizedEntryPoint) {
        this.unauthorizedEntryPoint = unauthorizedEntryPoint;
    }

    public void init(ServerHttpSecurity http) {
        var context = ServerHttpSecurityUtil.getContext(http);

        properties = context.getBean(DefaultSecurityProperties.class);

        restTemplate = ServerHttpSecurityUtil.getBean(http, RestTemplate.class, restTemplate());
        checkPermission = ServerHttpSecurityUtil.getBean(http, ICheckPermission.class, new DefaultCheckPermission());
        authorizationService = ServerHttpSecurityUtil.getBean(http, AuthorizationService.class, new RestAuthorizationService(restTemplate, properties));
        authenticationManager = ServerHttpSecurityUtil.getBean(http, ReactiveAuthenticationManager.class, new DefaultAuthenticationManager(authorizationService));
        authorizationManager = ServerHttpSecurityUtil.getBean(http, ReactiveAuthorizationManager.class, new DefaultAuthorizationManager(checkPermission));
        failureEntryPoint = (ServerAuthenticationEntryPoint) ServerHttpSecurityUtil.getBean(http, "failureEntryPoint", new DefaultAuthenticationFailureEntryPoint());
        successHandler = ServerHttpSecurityUtil.getBean(http, ServerAuthenticationSuccessHandler.class, new DefaultAuthenticationSuccessHandler());
        accessDeniedHandler = ServerHttpSecurityUtil.getBean(http, ServerAccessDeniedHandler.class, new DefaultAccessDeniedHandler(restTemplate, properties));
        unauthorizedEntryPoint = (ServerAuthenticationEntryPoint) ServerHttpSecurityUtil.getBean(http, "unauthorizedEntryPoint", new DefaultUnauthorizedEntryPoint(restTemplate, properties));
        converter = ServerHttpSecurityUtil.getBean(http, ServerAuthenticationConverter.class, new ServerBearerTokenAuthenticationConverter(true));
    }

    public void config(ServerHttpSecurity http) {
        WebFilter errorWebFilter = (WebFilter) ServerHttpSecurityUtil.getBean(http, "errorWebFilter", errorWebFilter());
        http.addFilterBefore(errorWebFilter, SecurityWebFiltersOrder.FIRST);

        WebFilter authenticationWebFilter = (WebFilter) ServerHttpSecurityUtil.getBean(http, "authenticationWebFilter", authenticationWebFilter());
        http.addFilterAt(authenticationWebFilter, SecurityWebFiltersOrder.AUTHENTICATION);

        http.exceptionHandling(c -> c
                .accessDeniedHandler(accessDeniedHandler)
                .authenticationEntryPoint(unauthorizedEntryPoint)
        );

        List<String> all = permitResource();

        http.authorizeExchange((authorize) -> authorize
                .pathMatchers(all.toArray(new String[0])).permitAll()  //无需进行权限过滤的请求路径:"/token", "/token/**", "/refresh_token", "/oauth2/**", "/logout"
                .pathMatchers("/**").access(authorizationManager)
                .anyExchange().authenticated()
        );
    }

    private List<String> permitResource() {
        List<String> whitelist = properties.getWhitelist();
        List<String> staticlist = properties.getStaticlist();
        List<String> all = new ArrayList<>();
        all.addAll(whitelist);
        all.addAll(staticlist);
        if (!all.contains("/*/public/**")) {
            //开放每个微服务的公共服务，比如app后台请求token
            all.add(0, "/*/public/**");
        }
        if (!all.contains("/webjars/**")) {
            all.add("/webjars/**");
        }
        if (!all.contains("/v3/api-docs/**")) {
            all.add("/v3/api-docs/**");
        }
        if (!all.contains("/swagger-ui/**")) {
            all.add("/swagger-ui/**");
        }
        if (!all.contains("/doc.html")) {
            all.add("/doc.html");
        }
        if (!all.contains("/doc.html**")) {
            all.add("/doc.html**");
        }
        return all;
    }
    private WebFilter authenticationWebFilter() {
        //认证处理器
        //oauth2认证过滤器
        DefaultAuthenticationWebFilter oauth2Filter = new DefaultAuthenticationWebFilter(authenticationManager);
        oauth2Filter.setServerAuthenticationConverter(converter);
        oauth2Filter.setAuthenticationFailureHandler(new ServerAuthenticationEntryPointFailureHandler(failureEntryPoint));
        oauth2Filter.setAuthenticationSuccessHandler(successHandler);
        return oauth2Filter;
    }

    private static WebFilter errorWebFilter() {
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

    private RestTemplate restTemplate() {
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
}
