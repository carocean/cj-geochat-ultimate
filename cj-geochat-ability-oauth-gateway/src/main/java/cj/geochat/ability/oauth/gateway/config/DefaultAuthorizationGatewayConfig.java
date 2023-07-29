package cj.geochat.ability.oauth.gateway.config;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.gateway.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.gateway.oauth2.OAuth2AuthorizationGatewayConfiguration;
import cj.geochat.ability.oauth.gateway.properties.DefaultSecurityProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;
import reactor.netty.ByteBufFlux;

import java.util.HashMap;
import java.util.Map;

@Configuration
@EnableWebFluxSecurity
@EnableConfigurationProperties(DefaultSecurityProperties.class)
public class DefaultAuthorizationGatewayConfig {

    @Bean
    SecurityWebFilterChain springWebFilterChain(ServerHttpSecurity http) {
        //这个filter必须放到前面设置
        OAuth2AuthorizationGatewayConfiguration.applyDefaultSecurity(http)
//                .setAuthorizationService();
        ;

        // @formatter:off
        http
                .cors(Customizer.withDefaults())
                .csrf(c->c.disable())
                .headers(c->c.frameOptions(o->o.disable()))
                .logout(c->c.disable())
                .formLogin(c->c.disable())
                .anonymous(c->c.disable())
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint((exchange, authException) -> {
                         var response=  exchange.getResponse();
                            response.getHeaders().setContentType(MediaType.APPLICATION_JSON_UTF8);
//                            ResultCode rc = ResultCodeTranslator.translateException(authException);
                            ResultCode rc = ResultCode.UNAUTHORIZED_CLIENT;
                            Map<String, String> map = new HashMap<>();
                            if (authException instanceof OAuth2AuthenticationException e) {
                                map.put("errorCode", e.getError().getErrorCode());
                                map.put("description", e.getError().getDescription());
                            } else {
                                map.put("exception", authException.getMessage());
                            }
                            Object obj = R.of(rc, map);
                            byte[] data=null;
                            try{
                                data=new ObjectMapper().writeValueAsString(obj).getBytes("UTF-8");
                            }catch (Exception e){
                                data=new byte[0];
                            }
                            return response
                                    .writeAndFlushWith(Flux
                                            .just(ByteBufFlux
                                                    .just(response
                                                            .bufferFactory()
                                                            .wrap(data)
                                                    )
                                            )
                                    );
                        }).accessDeniedHandler((exchange, accessDeniedException) -> {
                            var response=  exchange.getResponse();
                            response.getHeaders().setContentType(MediaType.APPLICATION_JSON_UTF8);
                            ResultCode rc = ResultCode.ACCESS_DENIED;
                            Map<String, String> map = new HashMap<>();
                            map.put("exception", accessDeniedException.getMessage());
                            Object obj = R.of(rc, map);
                            byte[] data=null;
                            try{
                                data=new ObjectMapper().writeValueAsString(obj).getBytes("UTF-8");
                            }catch (Exception e){
                                data=new byte[0];
                            }
                            return response
                                    .writeAndFlushWith(Flux
                                            .just(ByteBufFlux
                                                    .just(response
                                                            .bufferFactory()
                                                            .wrap(data)
                                                    )
                                            )
                                    );
                        })
                )
                ;
        // @formatter:on
        return http.build();
    }

}
