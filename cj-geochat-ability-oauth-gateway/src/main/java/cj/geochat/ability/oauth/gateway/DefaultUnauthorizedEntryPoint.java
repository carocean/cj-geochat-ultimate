package cj.geochat.ability.oauth.gateway;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.gateway.properties.DefaultSecurityProperties;
import cj.geochat.ability.oauth.gateway.util.QueryStringUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 未登录却访问网关会进入此类
 * * <pre>告知调用者登录和用户确认页地址，让调用者去跳转。</pre>
 */
public class DefaultUnauthorizedEntryPoint implements ServerAuthenticationEntryPoint {
    RestTemplate restTemplate;
    List<String> authServerUrls;

    public DefaultUnauthorizedEntryPoint(RestTemplate restTemplate, DefaultSecurityProperties defaultSecurityProperties) {
        this.authServerUrls = defaultSecurityProperties.getConnectCheckTokenUrl();
        this.restTemplate = restTemplate;
    }

    @SneakyThrows
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException e) {
        ServerHttpResponse response = exchange.getResponse();
        ServerHttpRequest request = exchange.getRequest();
        Map<String, String> params = request.getQueryParams().toSingleValueMap();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        Map<String, Object> map = new HashMap<>();
        String queryString = "";
        if (!map.isEmpty()) {
            queryString = QueryStringUtils.queryString(params);
            map.put("queryString", queryString);
        }
//        getAndFillAuthUrl(map);
        ResultCode rc = ResultCode.UNAUTHORIZED_CLIENT;
        Object obj = R.of(rc, map);
        return response.writeAndFlushWith(Flux.just(ByteBufFlux.just(response.bufferFactory().wrap(new ObjectMapper().writeValueAsString(obj).getBytes("UTF-8")))));
    }

    private void getAndFillAuthUrl(Map<String, Object> map) {
        String url = String.format("%s/oauth/auth_page_address", authServerUrls.get(0));
        Map<String, Object> resultMap = restTemplate.getForObject(url, Map.class);
        map.putAll(resultMap);
    }
}

