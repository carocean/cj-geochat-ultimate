package cj.geochat.ability.oauth.gateway.oauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

public class OAuth2AuthorizationGatewayConfiguration {
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityWebFilterChain authorizationServerSecurityFilterChain(ServerHttpSecurity http) throws Exception {
        applyDefaultSecurity(http);
        return http.build();
    }

    // @formatter:off
    public static OAuth2AuthorizationGatewayConfigurer applyDefaultSecurity(ServerHttpSecurity http) {
        var configurer=new OAuth2AuthorizationGatewayConfigurer();
        configurer.init(http);
        configurer.config(http);
        return configurer;
    }

}
