package cj.geochat.ability.oauth2.gateway;

import cj.geochat.ability.oauth2.userdetails.GeochatUser;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

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
public class Oauth2AuthSuccessHandler implements ServerAuthenticationSuccessHandler {
    ITenantStore tenantStore;

    public Oauth2AuthSuccessHandler(ITenantStore tenantStore) {
        this.tenantStore = tenantStore;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
//        ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
        MultiValueMap<String, String> headerValues = new LinkedMultiValueMap<>(4);
        headerValues.add("x-from-gateway", "true");
        Object principalObj = authentication.getPrincipal();
        String x_principal = "";
        String x_userid = "";
        //客户端也可自定一个User来安放登录身份
        if (principalObj instanceof User) {
            if (principalObj instanceof GeochatUser) {
                GeochatUser user = (GeochatUser) principalObj;
                x_principal = user.getUsername();
                x_userid = user.getUserId();
            }else {
                User user = (User) principalObj;
                x_principal = user.getUsername();
            }
        } else {
            x_principal = principalObj + "";
        }
        headerValues.add("x-opencode", x_principal);
        headerValues.add("x-userid", x_userid);
        OAuth2Authentication oauth2Authentication = (OAuth2Authentication) authentication;
        String clientId = oauth2Authentication.getOAuth2Request().getClientId();
        headerValues.add("x-appkey", clientId);

        //从认证服务器过来，如果认证服务器通过了租户认证则会有details
        Map<String, Object> details = (Map<String, Object>) authentication.getDetails();
        String tenantid = details == null ? "" : (String) details.getOrDefault("tenantid", "");
        if (!StringUtils.hasText(tenantid)) {
            String platformClientId = "platform";
            tenantid = tenantStore.readTenantId(x_principal, platformClientId);
        }
        headerValues.set("x-tenantid", tenantid);

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
