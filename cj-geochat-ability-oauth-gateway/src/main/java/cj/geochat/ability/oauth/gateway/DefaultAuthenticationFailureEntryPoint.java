package cj.geochat.ability.oauth.gateway;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.ByteBufFlux;

import java.util.HashMap;
import java.util.Map;

/**
 * 401未授权异常处理，转换为JSON
 *
 * @author zlt
 * @date 2019/10/7
 * <p>
 * Blog: https://zlt2000.gitee.io
 * Github: https://github.com/zlt2000
 */
@Slf4j
public class DefaultAuthenticationFailureEntryPoint implements ServerAuthenticationEntryPoint {
    @SneakyThrows
    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException exception) {
        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        ResultCode rc = ResultCode.UNAUTHORIZED_CLIENT;
        Map<String, String> map = new HashMap<>();
        if (exception instanceof OAuth2AuthenticationException e) {
            map.put("errorCode", e.getError().getErrorCode());
            map.put("description", e.getError().getDescription());
        } else {
            map.put("exception", exception.getMessage());
        }
        Object r = R.of(rc, map);
        return response.writeAndFlushWith(Flux.just(ByteBufFlux.just(response.bufferFactory().wrap(new ObjectMapper().writeValueAsString(r).getBytes("UTF-8")))));
    }
}
