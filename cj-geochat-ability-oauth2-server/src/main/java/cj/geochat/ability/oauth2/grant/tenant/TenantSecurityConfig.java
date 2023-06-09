package cj.geochat.ability.oauth2.grant.tenant;

import cj.geochat.ability.oauth2.redis.ITenantStore;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
public class TenantSecurityConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    @Autowired
    private TokenStore tokenStore;
    @Autowired
    private ITenantStore tenantStore;
    @Override
    public void configure(HttpSecurity http) throws Exception {
        TenantAuthenticationProvider provider = new TenantAuthenticationProvider(tokenStore,tenantStore);
        http.authenticationProvider(provider);
    }
}
