package cj.geochat.ability.oauth2.grant.sms;

import cj.geochat.ability.oauth2.grant.IGrantTypeCombin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;

@Component
public class SmsCodeGrantTypeCombin implements IGrantTypeCombin {
    @Autowired
    SmsCodeSecurityConfig smsCodeSecurityConfig;

    @Override
    public String getGrantType() {
        return SmsCodeTokenGranter.GRANT_TYPE;
    }

    @Override
    public AbstractAuthenticationToken tryGetAuthenticationToken(HttpServletRequest request) {
        // 获取参数
        String phone_num = request.getParameter("phone_num");
        String smsCode = request.getParameter("sms_code");
        if (StringUtils.hasText(phone_num) && StringUtils.hasText(smsCode)) {
            return new SmsCodeAuthenticationToken(phone_num, smsCode);
        }
        return null;
    }

    @Override
    public SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> getSecurityConfig() {
        return smsCodeSecurityConfig;
    }

    @Override
    public TokenGranter getTokenGranter(AuthenticationManager authenticationManager, AuthorizationServerEndpointsConfigurer endpoints) {
        return  new SmsCodeTokenGranter(authenticationManager, endpoints.getTokenServices(), endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory());
    }
}
