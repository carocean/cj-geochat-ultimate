package cj.geochat.ability.oauth.gateway;

import cj.geochat.ability.oauth.gateway.principal.DefaultAppPrincipal;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 认证成功处理类
 *
 * @author zlt
 * @date 2019/10/7
 * <p>
 * Blog: https://zlt2000.gitee.io
 * Github: https://github.com/zlt2000
 */
//y认证成功之后走这个
public class DefaultAuthenticationSuccessHandler implements ServerAuthenticationSuccessHandler {

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
//        ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
        MultiValueMap<String, String> headerValues = new LinkedMultiValueMap<>(4);
        headerValues.add("x-from-gateway", "true");
        Object principalObj = authentication.getPrincipal();
        String x_user = "";
        String x_account = "";
        String x_app_id = "";
        //客户端也可自定一个User来安放登录身份
        if (principalObj instanceof DefaultAppPrincipal principal) {
            x_user = principal.getName();
            x_account=principal.getAccount();
            x_app_id = principal.getAppid();
        } else {
            User user = (User) principalObj;
            x_user = user.getUsername();
        }
        headerValues.add("x-user", x_user);
        headerValues.add("x-account", x_account);
        headerValues.add("x-app-id", x_app_id);

        String roles = "";
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            roles += String.format("%s,", authority.getAuthority());
        }
        if (roles.endsWith(",")) {
            roles = roles.substring(0, roles.length() - 1);
        }
        headerValues.add("x-roles", roles);
//        String accountType = AuthUtils.getAccountType(oauth2Authentication.getUserAuthentication());
//        if (StrUtil.isNotEmpty(accountType)) {
//            headerValues.add(SecurityConstants.ACCOUNT_TYPE_HEADER, accountType);
//        }
        ServerWebExchange exchange = webFilterExchange.getExchange();
        ServerHttpRequest serverHttpRequest = exchange.getRequest().mutate()
                .headers(h -> h.addAll(headerValues))
                .build();

        ServerWebExchange build = exchange.mutate().request(serverHttpRequest).build();
        return webFilterExchange.getChain().filter(build);
    }
}
