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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 不合法的令牌或无权限会进入此类。
 * <pre>
 *     协议响应调用者，被拒后调用者可自行决定是否重定向到登录页
 * </pre>
 */
public class DefaultAccessDeniedHandler implements ServerAccessDeniedHandler {
    RestTemplate restTemplate;
    List<String> authServerUrls;

    public DefaultAccessDeniedHandler(RestTemplate restTemplate, DefaultSecurityProperties defaultSecurityProperties) {
        this.authServerUrls = defaultSecurityProperties.getConnectCheckTokenUrl();
        this.restTemplate = restTemplate;
    }

    @SneakyThrows
    @Override
    public Mono<Void> handle(ServerWebExchange serverWebExchange, AccessDeniedException e) {
        ServerHttpResponse response = serverWebExchange.getResponse();
        ServerHttpRequest request = serverWebExchange.getRequest();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        Map<String, String> params = request.getQueryParams().toSingleValueMap();
        Map<String, Object> map = new HashMap<>();
        String queryString = "";
        if (!map.isEmpty()) {
            queryString = QueryStringUtils.queryString(params);
            map.put("queryString", queryString);
        }
//        getAndFillAuthUrl(map);
        ResultCode rc = ResultCode.ACCESS_DENIED;
        Object obj = R.of(rc, map);
        return response.writeAndFlushWith(Flux.just(ByteBufFlux.just(response.bufferFactory().wrap(new ObjectMapper().writeValueAsString(obj).getBytes("UTF-8")))));
    }

    private void getAndFillAuthUrl(Map<String, Object> map) {
        String url = String.format("%s/oauth/auth_page_address", authServerUrls);
        Map<String, Object> resultMap = restTemplate.getForObject(url, Map.class);
        map.putAll(resultMap);
    }
}

