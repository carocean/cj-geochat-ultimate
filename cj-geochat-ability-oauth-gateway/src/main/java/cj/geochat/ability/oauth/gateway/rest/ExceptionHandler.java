package cj.geochat.ability.oauth.gateway.rest;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.gateway.ResultCodeTranslator;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.HashMap;
import java.util.Map;

@Component
@Order(-3) //这里将全局错误处理程序的顺序设置为-3。这是为了让它比 @Order(-1) 注册的 DefaultErrorWebExceptionHandler 处理程序更高的优先级。
@Slf4j
public class ExceptionHandler implements ErrorWebExceptionHandler {
    @SneakyThrows
    @Override
    public Mono<Void> handle(ServerWebExchange serverWebExchange, Throwable throwable) {
        ServerHttpResponse response = serverWebExchange.getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON_UTF8);
        ResultCode rc = (throwable instanceof AuthenticationException e) ? ResultCodeTranslator.translateException(e) : ResultCode.ERROR_UNKNOWN;
        Map<String, Object> map = new HashMap<>();
        map.put("exception", throwable.getMessage());
        Object obj = R.of(rc, map);
        byte[] data = null;
        try {
            data = new ObjectMapper().writeValueAsString(obj).getBytes("UTF-8");
        } catch (Exception e) {
            data = new byte[0];
        }
        DataBuffer buff = response.bufferFactory().wrap(data);//非池化内存
        return response.writeWith(Mono.just(buff));

    }
}