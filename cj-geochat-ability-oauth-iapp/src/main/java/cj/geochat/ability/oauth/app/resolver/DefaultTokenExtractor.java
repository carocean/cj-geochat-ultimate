package cj.geochat.ability.oauth.app.resolver;

import cj.geochat.ability.oauth.app.TokenExtractor;
import cj.geochat.ability.oauth.app.AppType;
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
        String appTypeStr = request.getHeader("x-app-type");
        if (!StringUtils.hasText(appTypeStr)) {
            appTypeStr = AppType.outsideApp.name();
        }
        var appType = AppType.valueOf(appTypeStr);
        //如果不是来自网关的swagger调用才进入以下处理。
        //因为在网关中已对swagger的调用解析了，并将swagger_token附到了请求的header中供网关解析
        if (appType != AppType.insideApp) {
            String swaggerToken = request.getHeader("swagger_token");
            if (StringUtils.hasText(swaggerToken)) {
                return extractSwaggerToken(swaggerToken, appType, request);
            }
        }
        String userid = request.getHeader("x-user");
        if (!StringUtils.hasText(userid)) {//这说明是内部访问（不是经过网关的请求），改为匿名访问，除非使用swagger_token。
            Principal principal = new DefaultAppPrincipal("anonymous_user", "anonymous_appid");
            DefaultAppAuthenticationDetails details = new DefaultAppAuthenticationDetails(appType, request);
            Authentication authentication = new DefaultAppAuthentication(principal, details, new ArrayList<>());
            return authentication;
        }
        String appkey = request.getHeader("x-app-id");
        List<GrantedAuthority> authorityList = new ArrayList<>();
        String roles = request.getHeader("x-roles");
        if (StringUtils.hasText(roles)) {
            String roleArr[] = roles.split(",");
            for (String role : roleArr) {
                authorityList.add(new SimpleGrantedAuthority(role));
            }
        }
        Principal principal = new DefaultAppPrincipal( userid, appkey);
        DefaultAppAuthenticationDetails details = new DefaultAppAuthenticationDetails(appType, request);
        Authentication authentication = new DefaultAppAuthentication(principal, details, authorityList);
        return authentication;
    }

    private Authentication extractSwaggerToken(String swaggerToken, AppType appType, HttpServletRequest request) {
        //应用标识::登录账号.用户标识::角色1,角色2
        String[] terms = swaggerToken.split("::");
        if (terms.length != 4 && terms.length != 3) {
            String err = "swagger_token格式不正确，抽取令牌过程被中止，正确格式：应用标识::用户::角色1,角色2，如果某项为空但::分隔不能少";
            log.warn(err);
            throw new RuntimeException(err);
        }
        String user = terms[2];
        if (!StringUtils.hasText(user)) {
            throw new RuntimeException("swagger_token is not contain a user.");
        }
        int pos = user.lastIndexOf(".");
        String opencode = "";
        String userid = "";
        if (pos < 0) {
            opencode = user;
        } else {
            opencode = user.substring(0, pos);
            userid = user.substring(pos + 1, user.length());
        }
        String appkey = terms[1];
        List<GrantedAuthority> authorityList = new ArrayList<>();

        if (terms.length == 4) {
            String roles = terms[3];
            if (StringUtils.hasText(roles)) {
                String roleArr[] = roles.split(",");
                for (String role : roleArr) {
                    authorityList.add(new SimpleGrantedAuthority(role));
                }
            }
        }
        Principal principal = new DefaultAppPrincipal( userid, appkey);
        DefaultAppAuthenticationDetails details = new DefaultAppAuthenticationDetails(appType, request);
        Authentication authentication = new DefaultAppAuthentication(principal, details, authorityList);
        return authentication;
    }

}
