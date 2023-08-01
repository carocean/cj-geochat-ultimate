package cj.geochat.ability.oauth.app.resolver;

import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.app.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.app.OAuth2Error;
import cj.geochat.ability.oauth.app.TokenExtractor;
import cj.geochat.ability.oauth.app.principal.DefaultAppAuthentication;
import cj.geochat.ability.oauth.app.principal.DefaultAppAuthenticationDetails;
import cj.geochat.ability.oauth.app.principal.DefaultAppPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public final class DefaultTokenExtractor implements TokenExtractor {

    public Authentication resolve(final HttpServletRequest request) {
        if (isGatewayRequest(request)) {
            return resolveFromGateway(request);
        }
        if (isDirectRequest(request)) {
            return resolverFromDirect(request);
        }
//        OAuth2Error error = new OAuth2Error(ResultCode.ACCESS_DENIED.code(), ResultCode.ACCESS_DENIED.message(), null);
//        throw new OAuth2AuthenticationException(error);
        return null;
    }


    private boolean isGatewayRequest(HttpServletRequest request) {
        String isFromGatewayStr = request.getHeader("x-from-gateway");
        if (!StringUtils.hasText(isFromGatewayStr)) {
            isFromGatewayStr = "false";
        }
        boolean isFromGateway = Boolean.valueOf(isFromGatewayStr);
        return isFromGateway;
    }

    private Authentication resolveFromGateway(HttpServletRequest request) {
        String userid = request.getHeader("x-user");
        String account = request.getHeader("x-account");
        String appid = request.getHeader("x-app-id");
        List<GrantedAuthority> authorityList = new ArrayList<>();
        String roles = request.getHeader("x-roles");
        if (StringUtils.hasText(roles)) {
            String roleArr[] = roles.split(",");
            for (String role : roleArr) {
                authorityList.add(new SimpleGrantedAuthority(role));
            }
        }
        DefaultAppPrincipal principal = new DefaultAppPrincipal(userid, account, appid,authorityList);
        DefaultAppAuthenticationDetails details = new DefaultAppAuthenticationDetails(true, request);
        Authentication authentication = new DefaultAppAuthentication(principal, details);
        return authentication;
    }


    private boolean isDirectRequest(HttpServletRequest request) {
        //使用swagger直接访问内部应用，必须设置Authorization头，禁止通access_token访问
        String token = request.getHeader("authorization");
        if (StringUtils.hasText(token)) {
            token = request.getHeader("Authorization");
        }
        if (!StringUtils.hasText(token)) {
            return false;
        }
        return token.contains("::");
    }

    private Authentication resolverFromDirect(HttpServletRequest request) {
        String token = request.getHeader("authorization");
        if (StringUtils.hasText(token)) {
            token = request.getHeader("Authorization");
        }
        if (!token.startsWith("Bearer") && !token.startsWith("bearer")) {
            return null;
        }
        token = token.substring("bearer".length());
        while (token.startsWith(" ")) {
            token = token.substring(1);
        }
        //token格式：
        //应用标识::账户.用户::角色1,角色2
        String[] terms = token.split("::");
        if (terms.length != 3 && terms.length != 2) {
            String err = """
                    Swagger_ The token format is incorrect, and the token extraction process was aborted. The correct format is: Application ID:: User:: Role 1, Role 2. If an item is empty but:: Separation cannot be missing
                    """;
            log.warn(err);
            OAuth2Error error = new OAuth2Error(ResultCode.OAUTH2_ERROR.code(), err, null);
            throw new OAuth2AuthenticationException(error);
        }
        String userAndAccount = terms[1];
        if (!StringUtils.hasText(userAndAccount)) {
            OAuth2Error error = new OAuth2Error(ResultCode.OAUTH2_ERROR.code(), "swagger`s token is not contain a user.", null);
            throw new OAuth2AuthenticationException(error);
        }
        String account = "";
        String user = "";
        int pos = userAndAccount.lastIndexOf(".");
        //即缺少账户，userAndAccount当作用户串
        if (pos < 0) {
            user=userAndAccount;
        }else{
            account = userAndAccount.substring(0, pos);
            user = userAndAccount.substring(pos+1);
        }
        String appid = terms[0];
        List<GrantedAuthority> authorityList = new ArrayList<>();
        if (terms.length == 3) {
            String roles = terms[2];
            if (StringUtils.hasText(roles)) {
                String roleArr[] = roles.split(",");
                for (String role : roleArr) {
                    authorityList.add(new SimpleGrantedAuthority(role));
                }
            }
        }
        DefaultAppPrincipal principal = new DefaultAppPrincipal(user,account, appid,authorityList);
        DefaultAppAuthenticationDetails details = new DefaultAppAuthenticationDetails(false, request);
        Authentication authentication = new DefaultAppAuthentication(principal, details);
        return authentication;
    }


}
