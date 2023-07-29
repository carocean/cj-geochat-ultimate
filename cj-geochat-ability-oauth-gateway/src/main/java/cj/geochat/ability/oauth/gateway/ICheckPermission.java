package cj.geochat.ability.oauth.gateway;

import org.springframework.util.AntPathMatcher;

public interface ICheckPermission {
    /**
     * 判断该角色是否可访问该请求地址。如果可访问返回true
     *
     * @param antPathMatcher
     * @param role
     * @param accessUrl
     * @return
     */
    boolean check(AntPathMatcher antPathMatcher, String username, String role,  String accessUrl);

}
