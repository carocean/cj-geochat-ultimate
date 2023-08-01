package cj.geochat.ability.oauth.app.principal;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.StringUtils;

import java.security.Principal;
import java.util.Collection;
import java.util.stream.Collectors;

public class DefaultAppPrincipal implements Principal {

    String user;
    String account;
    String appid;
    boolean enabled;
    boolean accountNonExpired;
    boolean accountNonLocked;
    boolean credentialsNonExpire;
   private Collection<? extends GrantedAuthority> authorities;
    public DefaultAppPrincipal() {
    }

    public DefaultAppPrincipal(String user,String account, String appid,Collection<? extends GrantedAuthority> authorities) {
        this.user = user;
        this.account=account;
        this.appid = appid;
        this.authorities=authorities;
        enabled = true;
        accountNonExpired = true;
        accountNonLocked = true;
        credentialsNonExpire = true;
    }


    public String getAppid() {
        return appid;
    }

    @Override
    public String getName() {
        return user;
    }

    public String getAccount() {
        return account;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    public boolean isCredentialsNonExpire() {
        return credentialsNonExpire;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }

    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }

    public void setCredentialsNonExpire(boolean credentialsNonExpire) {
        this.credentialsNonExpire = credentialsNonExpire;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String toString() {
        String fullName = (StringUtils.hasText(appid) ? appid + "::" : "")
                + (StringUtils.hasText(account) ? account+"." : "")
                + (StringUtils.hasText(user) ? user : "");
        if (!authorities.isEmpty()) {
            fullName = fullName + "::" + authorities.stream().map(e -> e.getAuthority()).collect(Collectors.joining(","));
        }
        return fullName;
    }

    @Override
    public boolean equals(Object obj) {
        DefaultAppPrincipal other = (DefaultAppPrincipal) obj;
        if (other == null) {
            other = new DefaultAppPrincipal();
        }
        return this.toString().equals(other.toString());
    }
}
